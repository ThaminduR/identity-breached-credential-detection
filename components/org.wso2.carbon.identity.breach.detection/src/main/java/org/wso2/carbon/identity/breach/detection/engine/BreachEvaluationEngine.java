/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.breach.detection.engine;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.breach.source.BreachContext;
import org.wso2.carbon.identity.breach.source.BreachSource;
import org.wso2.carbon.identity.breach.source.BreachSourceException;
import org.wso2.carbon.identity.breach.source.BreachVerdict;
import org.wso2.carbon.identity.breach.source.FailureAction;
import org.wso2.carbon.identity.breach.source.Outcome;
import org.wso2.carbon.identity.breach.source.UnavailableCause;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Orders the sources a tenant enabled, bounds each call, stops at the first match, contains failures to the
 * source that caused them, and resolves the verdicts into one decision.
 * <p>
 * Knows nothing about any concrete source. Ordering comes from the priority each source declares, so a local
 * source runs before a network round trip and a match there costs no request.
 */
public class BreachEvaluationEngine {

    private static final Log LOG = LogFactory.getLog(BreachEvaluationEngine.class);

    private final SourceRegistry registry;
    private final ThreadPoolExecutor executor;
    private final int timeoutMs;

    public BreachEvaluationEngine(SourceRegistry registry, int workerThreads, int timeoutMs) {

        this.registry = registry;
        this.timeoutMs = timeoutMs;
        int threads = Math.max(1, workerThreads);
        AtomicInteger counter = new AtomicInteger();
        // Core size equals the maximum: a ThreadPoolExecutor only grows past the core size once the queue is
        // full, so a smaller core with a bounded queue would serialise every evaluation onto one thread.
        this.executor = new ThreadPoolExecutor(threads, threads, 60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(threads * 10),
                runnable -> {
                    Thread thread = new Thread(runnable, "breach-source-" + counter.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
        this.executor.allowCoreThreadTimeOut(true);
    }

    /**
     * Evaluate a candidate against every source this organization enabled. Clears the credential before
     * returning, unless a source timed out and may still be reading it.
     *
     * @param context the candidate and the organization it is being set in.
     * @return what the caller should do.
     */
    public Decision evaluate(BreachContext context) {

        List<BreachSource> plan = plan(context.getTenantDomain());
        if (plan.isEmpty()) {
            // No source wants to be consulted here, so nothing is being checked. That is a legitimate
            // state - it is what an organization that has not switched anything on looks like.
            context.getCredential().clear();
            return Decision.ACCEPT;
        }

        // Set when a call times out: the worker may still be reading the characters, so they are left to the
        // collector rather than zeroed underneath a call in flight.
        AtomicBoolean credentialInFlight = new AtomicBoolean();
        List<BreachVerdict> verdicts = new ArrayList<>(plan.size());

        for (BreachSource source : plan) {
            BreachVerdict verdict = call(source, idOf(source), context, credentialInFlight);
            verdicts.add(verdict);
            if (verdict.getOutcome() == Outcome.FOUND) {
                // A match ends it. Nothing after this needs asking, and no network call is worth making.
                break;
            }
        }

        if (!credentialInFlight.get()) {
            context.getCredential().clear();
        }
        return resolve(context.getTenantDomain(), plan, verdicts);
    }

    /**
     * Stop accepting work. Called when the component deactivates.
     */
    public void shutdown() {

        executor.shutdownNow();
    }

    /**
     * The sources this organization wants consulted, cheapest first. Only bound sources can appear, because
     * only a source can enable itself.
     */
    private List<BreachSource> plan(String tenantDomain) {

        List<BreachSource> planned = new ArrayList<>();
        // The registry already orders by declared priority, so an in-process source runs before a round trip.
        for (BreachSource source : registry.installed()) {
            try {
                if (source.isEnabled(tenantDomain)) {
                    planned.add(source);
                }
            } catch (Throwable t) {
                LOG.error("Breach source '" + source.getId() + "' failed to report whether it is enabled. "
                        + "It will not be consulted.", t);
            }
        }
        return planned;
    }

    private BreachVerdict call(BreachSource source, String sourceId, BreachContext context,
                               AtomicBoolean credentialInFlight) {

        Future<BreachVerdict> future;
        try {
            future = executor.submit(() -> invoke(source, context));
        } catch (RejectedExecutionException e) {
            return BreachVerdict.unavailable(sourceId, UnavailableCause.INTERNAL,
                    "Evaluation capacity is exhausted.");
        }
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            credentialInFlight.set(true);
            future.cancel(true);
            return BreachVerdict.unavailable(sourceId, UnavailableCause.TIMEOUT,
                    "The source did not answer within " + timeoutMs + " ms.");
        } catch (InterruptedException e) {
            credentialInFlight.set(true);
            Thread.currentThread().interrupt();
            future.cancel(true);
            return BreachVerdict.unavailable(sourceId, UnavailableCause.INTERNAL,
                    "The evaluation was interrupted.");
        } catch (Exception e) {
            return contain(sourceId, e.getCause() == null ? e : e.getCause());
        }
    }

    /**
     * The id, or a placeholder if the source cannot supply one. Nothing a source does may fail the write.
     */
    private static String idOf(BreachSource source) {

        try {
            return source.getId();
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private BreachVerdict invoke(BreachSource source, BreachContext context) {

        try {
            BreachVerdict verdict = source.evaluate(context);
            return verdict == null
                    ? BreachVerdict.unavailable(source.getId(), UnavailableCause.INTERNAL,
                            "The source returned no verdict.")
                    : verdict;
        } catch (BreachSourceException e) {
            return BreachVerdict.unavailable(source.getId(), e.getUnavailableCause(), e.getMessage());
        } catch (Throwable t) {
            return contain(source.getId(), t);
        }
    }

    private BreachVerdict contain(String sourceId, Throwable t) {

        // Contained to this source: one connector's defect must not take the others down with it.
        LOG.error("Breach source '" + sourceId + "' failed while evaluating a password. The source is treated "
                + "as unavailable and the remaining sources are unaffected.", t);
        return BreachVerdict.unavailable(sourceId, UnavailableCause.INTERNAL,
                "The source raised an unexpected error.");
    }

    /**
     * Resolve the verdicts into one decision. {@code verdicts.get(i)} is the verdict of {@code plan.get(i)},
     * so the source that produced a verdict is the one asked for its failure action.
     */
    private Decision resolve(String tenantDomain, List<BreachSource> plan, List<BreachVerdict> verdicts) {

        int answered = 0;
        String denyingSource = null;
        for (int i = 0; i < verdicts.size(); i++) {
            BreachVerdict verdict = verdicts.get(i);
            switch (verdict.getOutcome()) {
                case FOUND:
                    return Decision.REFUSE_BREACHED;
                case NOT_FOUND:
                    answered++;
                    break;
                default:
                    if (denyingSource == null
                            && failureActionOf(plan.get(i), tenantDomain) == FailureAction.DENY) {
                        denyingSource = verdict.getSourceId();
                    }
            }
        }

        int unavailable = verdicts.size() - answered;
        if (unavailable > 0 && answered == 0) {
            // The signal that matters most: everything looks healthy from outside while nothing is checked.
            LOG.error("Breached password detection is not enforcing for tenant '" + tenantDomain
                    + "': no enabled source could return a verdict. Verdicts: " + verdicts);
        } else if (unavailable > 0 && LOG.isWarnEnabled()) {
            LOG.warn("Breached password detection is degraded for tenant '" + tenantDomain + "': " + unavailable
                    + " of " + verdicts.size() + " sources could not answer.");
        }

        return denyingSource == null ? Decision.ACCEPT : Decision.REFUSE_UNVERIFIED;
    }

    private FailureAction failureActionOf(BreachSource source, String tenantDomain) {

        try {
            return source.getFailureAction(tenantDomain);
        } catch (Throwable t) {
            LOG.error("Breach source '" + source.getId() + "' failed to report its failure action. "
                    + "Treating it as allow.", t);
            return FailureAction.ALLOW;
        }
    }
}
