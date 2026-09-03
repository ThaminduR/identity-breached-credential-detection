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

package org.wso2.carbon.identity.breach.detection;

/**
 * A breach intelligence source, published as an OSGi service.
 * <p>
 * Every method is abstract. A source states its own enablement, failure behaviour and configuration rather
 * than inheriting a default. The engine calls every source on a worker thread and applies the evaluation
 * timeout, so a source that blocks does not block the password write.
 */
public interface BreachSource {

    /**
     * @return a stable id, lowercase and without spaces. Deployment configuration is namespaced on it.
     */
    String getId();

    /**
     * @return the call order hint. The engine calls sources in ascending order of this value.
     */
    int getPriority();

    /**
     * Receive the resolved deployment settings. Called on bind, and again on reconfiguration.
     *
     * @param configuration resolved settings for this source.
     */
    void configure(SourceConfiguration configuration);

    /**
     * Whether this organization wants the source consulted, and whether the source has enough
     * configuration to answer. A source that cannot answer returns false. There is no separate check for
     * whether a source is configured.
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
     * Evaluate the candidate password.
     * <p>
     * Return {@link Outcome#UNAVAILABLE} for any result that is not a positive determination, and log the
     * reason. Do not return {@link Outcome#NOT_FOUND} when a call fails. Do not log, cache or transmit the
     * credential, and do not retain it after this method returns.
     *
     * @param credential   the candidate password. Do not retain it past this call.
     * @param tenantDomain the organization the password is being set in.
     * @return what this source concluded.
     */
    Outcome evaluate(Credential credential, String tenantDomain);
}
