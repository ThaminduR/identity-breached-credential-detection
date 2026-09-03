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
import org.wso2.carbon.identity.breach.detection.Credential;
import org.wso2.carbon.identity.breach.detection.BreachSource;
import org.wso2.carbon.identity.breach.detection.Outcome;

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
 * Evaluates a candidate password against the sources an organization enabled.
 * <p>
 * The engine orders the sources, bounds each call with the evaluation timeout, stops at the first match,
 * contains a failure to the source that caused it, and resolves the outcomes into one decision. It holds no
 * reference to any concrete source. Call order comes from the priority each source declares, so an
 * in-process source is called before one that makes a network request.
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
        // Core size equals the maximum. A ThreadPoolExecutor grows past the core size only once the queue
        // is full, so a smaller core with a bounded queue would serialise evaluations onto one thread. The
        // queue is bounded and the rejection policy aborts, so an overloaded server returns UNAVAILABLE
        // immediately instead of making every request wait out the timeout.
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
     * Evaluates a candidate against every source this organization enabled. Clears the credential before
     * returning, unless a source timed out and may still be reading it.
     *
     * @param credential   the candidate password.
     * @param tenantDomain the organization the password is being set in.
     * @return what the caller should do.
     */
    public Decision evaluate(Credential credential, String tenantDomain) {

        List<BreachSource> plan = plan(tenantDomain);
        if (plan.isEmpty()) {
            // No source is enabled, so nothing is checked. This is the expected state for an organization
            // that has not switched the feature on.
            credential.clear();
            return Decision.ACCEPT;
        }

        // Set when a call times out. The worker may still be reading the characters, so the array is left
        // for the garbage collector instead of being zeroed under a call that is still running.
        AtomicBoolean credentialInFlight = new AtomicBoolean();
        List<Outcome> outcomes = new ArrayList<>(plan.size());

        for (BreachSource source : plan) {
            Outcome outcome = call(source, idOf(source), credential, tenantDomain, credentialInFlight);
            outcomes.add(outcome);
            if (outcome == Outcome.FOUND) {
                // A match ends the evaluation. No later source is consulted.
                break;
            }
        }

        if (!credentialInFlight.get()) {
            credential.clear();
        }
        return resolve(tenantDomain, plan, outcomes);
    }

    /**
     * Stop accepting work. Called when the component deactivates.
     */
    public void shutdown() {

        executor.shutdownNow();
    }

    /**
     * @return the sources this organization enabled, cheapest first. Only a bound source can appear,
     * because enablement is the source's own decision.
     */
    private List<BreachSource> plan(String tenantDomain) {

        List<BreachSource> planned = new ArrayList<>();
        // The registry orders by declared priority, so an in-process source is called before a remote one.
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

    private Outcome call(BreachSource source, String sourceId, Credential credential, String tenantDomain,
                         AtomicBoolean credentialInFlight) {

        Future<Outcome> future;
        try {
            future = executor.submit(() -> invoke(source, sourceId, credential, tenantDomain));
        } catch (RejectedExecutionException e) {
            LOG.error("Breach source '" + sourceId + "' was not called: evaluation capacity is exhausted.");
            return Outcome.UNAVAILABLE;
        }
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            credentialInFlight.set(true);
            future.cancel(true);
            LOG.warn("Breach source '" + sourceId + "' did not answer within " + timeoutMs + " ms.");
            return Outcome.UNAVAILABLE;
        } catch (InterruptedException e) {
            credentialInFlight.set(true);
            Thread.currentThread().interrupt();
            future.cancel(true);
            LOG.warn("Evaluation of breach source '" + sourceId + "' was interrupted.");
            return Outcome.UNAVAILABLE;
        } catch (Exception e) {
            return contain(sourceId, e.getCause() == null ? e : e.getCause());
        }
    }

    /**
     * Returns the source id, or a placeholder when the source cannot supply one. A source must not be able
     * to fail the password write.
     */
    private static String idOf(BreachSource source) {

        try {
            return source.getId();
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private Outcome invoke(BreachSource source, String sourceId, Credential credential, String tenantDomain) {

        try {
            Outcome outcome = source.evaluate(credential, tenantDomain);
            if (outcome == null) {
                LOG.error("Breach source '" + sourceId + "' returned no outcome.");
                return Outcome.UNAVAILABLE;
            }
            return outcome;
        } catch (Throwable t) {
            return contain(sourceId, t);
        }
    }

    private Outcome contain(String sourceId, Throwable t) {

        // Contain the failure to this source so that a defect in one connector does not affect the others.
        LOG.error("Breach source '" + sourceId + "' failed while evaluating a password. The source is treated "
                + "as unavailable and the remaining sources are unaffected.", t);
        return Outcome.UNAVAILABLE;
    }

    /**
     * Resolve the outcomes into one decision. {@code outcomes.get(i)} came from {@code plan.get(i)}, so the
     * source that could not answer is the one asked for its failure action.
     */
    private Decision resolve(String tenantDomain, List<BreachSource> plan, List<Outcome> outcomes) {

        int answered = 0;
        boolean denied = false;
        for (int i = 0; i < outcomes.size(); i++) {
            switch (outcomes.get(i)) {
                case FOUND:
                    return Decision.REFUSE_BREACHED;
                case NOT_FOUND:
                    answered++;
                    break;
                default:
                    denied = denied || refuses(plan.get(i), tenantDomain);
            }
        }

        int unavailable = outcomes.size() - answered;
        if (unavailable > 0 && answered == 0) {
            // Logged at ERROR: the feature reports itself as enabled while no password is being checked.
            LOG.error("Breached password detection is not enforcing for tenant '" + tenantDomain
                    + "': no enabled source could return a verdict. " + describe(plan, outcomes));
        } else if (unavailable > 0 && LOG.isWarnEnabled()) {
            LOG.warn("Breached password detection is degraded for tenant '" + tenantDomain + "': " + unavailable
                    + " of " + outcomes.size() + " sources could not answer. " + describe(plan, outcomes));
        }

        return denied ? Decision.REFUSE_UNVERIFIED : Decision.ACCEPT;
    }

    /**
     * Describes which source returned which outcome, for one log line. Each source logs its own reason.
     */
    private static String describe(List<BreachSource> plan, List<Outcome> outcomes) {

        StringBuilder text = new StringBuilder("Outcomes: ");
        for (int i = 0; i < outcomes.size(); i++) {
            if (i > 0) {
                text.append(", ");
            }
            text.append(idOf(plan.get(i))).append('=').append(outcomes.get(i));
        }
        return text.toString();
    }

    private boolean refuses(BreachSource source, String tenantDomain) {

        try {
            return source.refusesWhenUnavailable(tenantDomain);
        } catch (Throwable t) {
            LOG.error("Breach source '" + idOf(source) + "' failed to report its failure action. Allowing.", t);
            return false;
        }
    }
}
