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
 * A breach intelligence source, published as an OSGi service. A source owns its own timeouts, retries
 * and failure policy. {@link #check} runs on the calling thread and is not bounded by the engine.
 */
public interface BreachSource {

    String getId();

    int getPriority();

    void configure(SourceConfiguration configuration);

    boolean isEnabled(String tenantDomain);

    /**
     * Returns {@link Decision#REFUSE_BREACHED} when the password is in this source's data. When the data
     * cannot be reached, apply the source's own failure policy. Never log, cache or transmit the
     * credential, and do not retain it after this returns.
     */
    Decision check(Credential credential, String tenantDomain);
}
