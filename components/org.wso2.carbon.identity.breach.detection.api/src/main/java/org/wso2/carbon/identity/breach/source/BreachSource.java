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

package org.wso2.carbon.identity.breach.source;

import java.util.Collections;
import java.util.List;

/**
 * A breach-intelligence source, published as an OSGi service.
 * <p>
 * The engine <em>discovers</em> sources rather than knowing them, so a source describes itself well enough that
 * the engine can order it and the configuration layer can resolve its settings - neither of which can be
 * hard-coded against a source that did not exist when the core was built.
 * <p>
 * Register from a connector's activator:
 * <pre>{@code
 * bundleContext.registerService(BreachSource.class, new HibpBreachSource(), null);
 * }</pre>
 * <p>
 * Everything but {@link #getId()} and {@link #evaluate(BreachContext)} has a default, and the contract gains
 * default methods rather than abstract ones, so an existing connector keeps compiling across additive
 * revisions.
 */
public interface BreachSource {

    /**
     * A stable id. Deployment configuration is namespaced on it ({@code [breach_detection.sources.<id>]}) and
     * log lines are labelled with it. Lowercase, no spaces.
     *
     * @return the source id.
     */
    String getId();

    /**
     * The deployment settings this source needs. The core resolves them and hands them back through
     * {@link #configure(SourceConfiguration)}.
     *
     * @return declared settings; empty if the source needs none.
     */
    default List<PropertyDescriptor> getProperties() {

        return Collections.emptyList();
    }

    /**
     * A cost hint. The engine sorts ascending, so an in-process source declaring a low number is consulted
     * before a network round trip without the engine knowing what either one is.
     *
     * @return the priority; lower runs first.
     */
    default int getPriority() {

        return 1000;
    }

    /**
     * Whether this source answers without crossing the deployment boundary.
     * <p>
     * An offline source is called on the calling thread: it answers in microseconds, so a thread hand-off would
     * cost more than the lookup. Anything else is bounded by the configured timeout on a worker thread.
     *
     * @return {@code true} if no network call is involved.
     */
    default boolean isOffline() {

        return false;
    }

    /**
     * Hand the source its resolved deployment settings. Called on bind. A source must tolerate being
     * reconfigured while evaluations are in flight.
     *
     * @param configuration resolved settings for this source.
     */
    default void configure(SourceConfiguration configuration) {

    }

    /**
     * Whether this source is set up well enough to be called. Separates "not set up" from "set up and
     * failing" - the distinction that keeps a non-operational source from reporting itself as enforcing.
     *
     * @param tenantDomain the tenant asking.
     * @return {@code true} if the source can be called.
     */
    default boolean isConfigured(String tenantDomain) {

        return true;
    }

    /**
     * Whether this organization wants this source consulted.
     * <p>
     * The source owns this decision, and owns whatever configuration surface it needs to let an administrator
     * make it. A source backed by a file answers from whether the file loaded; a source backed by a hosted
     * service answers from its own governance configuration, which is also what gives it a Console presence
     * when its bundle is installed and takes that presence away when it is removed.
     * <p>
     * The default is {@code false}, so a source is consulted only when it says so.
     *
     * @param tenantDomain the organization asking.
     * @return {@code true} if the source should be consulted for this organization.
     */
    default boolean isEnabled(String tenantDomain) {

        return false;
    }

    /**
     * What to do with a password this source could not check, for this organization.
     *
     * @param tenantDomain the organization asking.
     * @return the action to take when this source returns {@link Outcome#UNAVAILABLE}.
     */
    default FailureAction getFailureAction(String tenantDomain) {

        return FailureAction.ALLOW;
    }

    /**
     * Reach a verdict on the candidate password.
     * <p>
     * Return {@link Outcome#UNAVAILABLE} - or throw {@link BreachSourceException} - for anything that is not a
     * positive determination. Never return {@link Outcome#NOT_FOUND} because a call failed. Never log, cache,
     * or transmit the credential in a recoverable form, and never retain it past this call.
     *
     * @param context the candidate password and where it is being set.
     * @return the verdict.
     * @throws BreachSourceException if no verdict could be produced.
     */
    BreachVerdict evaluate(BreachContext context) throws BreachSourceException;
}
