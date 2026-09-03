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

package org.wso2.carbon.identity.breach.detection.spi;

import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;

/**
 * A breach intelligence source, published as an OSGi service.
 * <p>
 * A source owns everything about how it reaches its data. It sets its own timeouts, retries and failure
 * handling, and it decides what happens to a password it could not check. The engine calls
 * {@link #check} on the calling thread and does not bound it, so a source that makes a network request must
 * apply its own timeout.
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
     * Whether this organization wants the source consulted, and whether the source has enough configuration
     * to answer. A source that cannot answer returns false.
     *
     * @param tenantDomain the organization asking.
     * @return true if the source should be consulted.
     */
    boolean isEnabled(String tenantDomain);

    /**
     * Check the candidate password and decide the result.
     * <p>
     * Return {@link Decision#REFUSE_BREACHED} when the password is in this source's data. Return
     * {@link Decision#ACCEPT} when it is not. When the source cannot reach its data, log the reason and
     * return either {@link Decision#REFUSE_UNVERIFIED} or {@link Decision#ACCEPT} according to the failure
     * policy configured for the source. Do not log, cache or transmit the credential, and do not retain it
     * after this method returns.
     *
     * @param credential   the candidate password.
     * @param tenantDomain the organization the password is being set in.
     * @return what the server should do with this password.
     */
    Decision check(Credential credential, String tenantDomain);
}
