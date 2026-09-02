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
 * Orders the sources a tenant enabled, bounds each call, short-circuits on the first match, contains failures
 * to the source that caused them, and resolves the whole thing into one decision.
 * <p>
 * It knows nothing about any concrete source. Ordering comes from the priority each source declares, so an
 * in-process offline list is consulted before a network round trip - which means the passwords an operator most
 * wants blocked never leave the deployment and never consume third-party quota.
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
        this.executor = new ThreadPoolExecutor(1, threads, 60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(threads * 10),
                runnable -> {
                    Thread thread = new Thread(runnable, "breach-source-" + counter.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    /**
     * Evaluate a candidate against every source this organization enabled.
     * <p>
     * Clears the credential before returning, unless a source timed out and may still be reading it. The
     * caller does not need to clear it again.
     *
     * @param context the candidate and its surrounding operation.
     * @return the decision, the reported status, and every contributing verdict.
     */
    public EvaluationResult evaluate(BreachContext context) {

        List<BreachSource> plan = plan(context.getTenantDomain());
        if (plan.isEmpty()) {
            // No source wants to be consulted here, so nothing is being checked. That is a legitimate
            // state - it is what an organization that has not switched anything on looks like.
            context.getCredential().clear();
            return EvaluationResult.accept(EnforcementStatus.OFF);
        }

        // Set when a call times out: the worker may still be reading the characters, so they are left to the
        // collector rather than zeroed underneath a call in flight.
        AtomicBoolean credentialInFlight = new AtomicBoolean();
        List<BreachVerdict> verdicts = new ArrayList<>(plan.size());

        for (BreachSource source : plan) {
            BreachVerdict verdict = call(source, context, credentialInFlight);
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
     * The sources this organization wants consulted, cheapest first.
     * <p>
     * Only bound sources can appear, because the only thing that can enable one is the source itself. That
     * removes an entire failure mode: there is no way to name a source the deployment does not have.
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

    private BreachVerdict call(BreachSource source, BreachContext context, AtomicBoolean credentialInFlight) {

        String sourceId = source.getId();
        try {
            if (!source.isConfigured(context.getTenantDomain())) {
                return BreachVerdict.unavailable(sourceId, UnavailableCause.MISCONFIGURED,
                        "The source is installed but not configured.");
            }
        } catch (Throwable t) {
            return contain(sourceId, t);
        }

        if (source.isOffline()) {
            // In-process and answering in microseconds. A thread hand-off would cost more than the lookup.
            return invoke(source, context);
        }

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
    private EvaluationResult resolve(String tenantDomain, List<BreachSource> plan,
                                     List<BreachVerdict> verdicts) {

        int answered = 0;
        String denyingSource = null;
        for (int i = 0; i < verdicts.size(); i++) {
            BreachVerdict verdict = verdicts.get(i);
            switch (verdict.getOutcome()) {
                case FOUND:
                    return EvaluationResult.of(Decision.REFUSE_BREACHED, EnforcementStatus.ENFORCING, verdicts,
                            verdict.getSourceId());
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
        EnforcementStatus status = enforcementStatus(answered, unavailable);
        if (status == EnforcementStatus.NOT_ENFORCING) {
            // The signal that matters most: everything looks healthy from outside while nothing is checked.
            LOG.error("Breached password detection is not enforcing for tenant '" + tenantDomain
                    + "': no enabled source could return a verdict. Verdicts: " + verdicts);
        } else if (status == EnforcementStatus.DEGRADED && LOG.isWarnEnabled()) {
            LOG.warn("Breached password detection is degraded for tenant '" + tenantDomain + "': " + unavailable
                    + " of " + verdicts.size() + " sources could not answer.");
        }

        return denyingSource == null
                ? EvaluationResult.of(Decision.ACCEPT, status, verdicts, null)
                : EvaluationResult.of(Decision.REFUSE_UNVERIFIED, status, verdicts, denyingSource);
    }

    private static EnforcementStatus enforcementStatus(int answered, int unavailable) {

        if (unavailable == 0) {
            return EnforcementStatus.ENFORCING;
        }
        return answered > 0 ? EnforcementStatus.DEGRADED : EnforcementStatus.NOT_ENFORCING;
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
