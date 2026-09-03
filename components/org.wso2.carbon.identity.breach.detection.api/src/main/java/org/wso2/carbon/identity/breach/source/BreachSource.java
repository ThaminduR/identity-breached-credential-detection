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

import java.util.List;

/**
 * A breach-intelligence source, published as an OSGi service.
 * <p>
 * Every method is abstract, so enablement, failure action and configuration cannot be inherited by accident.
 * Every source is called on a worker thread and bounded by the evaluation timeout, so one that hangs cannot
 * hang the credential write.
 */
public interface BreachSource {

    /**
     * @return a stable id. Deployment configuration is namespaced on it. Lowercase, no spaces.
     */
    String getId();

    /**
     * @return the deployment settings this source needs, or an empty list.
     */
    List<PropertyDescriptor> getProperties();

    /**
     * @return a cost hint. The engine calls sources in ascending order.
     */
    int getPriority();

    /**
     * Receive the resolved deployment settings. Called on bind, and again on reconfiguration.
     *
     * @param configuration resolved settings for this source.
     */
    void configure(SourceConfiguration configuration);

    /**
     * Whether this organization wants the source consulted, and whether it is set up well enough to answer.
     * A source that is not configured reports false here; there is no separate configured check.
     *
     * @param tenantDomain the organization asking.
     * @return true if the source should be consulted.
     */
    boolean isEnabled(String tenantDomain);

    /**
     * @param tenantDomain the organization asking.
     * @return true to refuse a password this source could not check, false to let it through.
     */
    boolean refusesWhenUnavailable(String tenantDomain);

    /**
     * Reach a verdict on the candidate password.
     * <p>
     * Return {@link Outcome#UNAVAILABLE} for anything that is not a positive determination. Never return
     * {@link Outcome#NOT_FOUND} because a call failed. Never log, cache or transmit the credential, and do
     * not retain it past this call.
     *
     * @param context the candidate password and the organization it is being set in.
     * @return the verdict.
     */
    BreachVerdict evaluate(BreachContext context);
}
