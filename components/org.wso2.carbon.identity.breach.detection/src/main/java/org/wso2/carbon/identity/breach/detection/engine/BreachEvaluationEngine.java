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
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;

import java.util.ArrayList;
import java.util.List;

/**
 * Calls the sources an organization enabled and returns the first decision that is not
 * {@link Decision#ACCEPT}.
 * <p>
 * The engine holds no reference to any concrete source. Call order comes from the priority each source
 * declares, so an in-process source is called before one that makes a network request. Each source decides
 * what happens when it cannot reach its data, so the engine does not interpret failures.
 */
public class BreachEvaluationEngine {

    private static final Log LOG = LogFactory.getLog(BreachEvaluationEngine.class);

    private final SourceRegistry registry;

    public BreachEvaluationEngine(SourceRegistry registry) {

        this.registry = registry;
    }

    /**
     * Checks a candidate against every source this organization enabled, stopping at the first refusal.
     * Clears the credential before returning.
     *
     * @param credential   the candidate password.
     * @param tenantDomain the organization the password is being set in.
     * @return what the caller should do.
     */
    public Decision evaluate(Credential credential, String tenantDomain) {

        try {
            for (BreachSource source : enabledSources(tenantDomain)) {
                Decision decision = check(source, credential, tenantDomain);
                if (decision != Decision.ACCEPT) {
                    return decision;
                }
            }
            return Decision.ACCEPT;
        } finally {
            credential.clear();
        }
    }

    private List<BreachSource> enabledSources(String tenantDomain) {

        List<BreachSource> enabled = new ArrayList<>();
        for (BreachSource source : registry.installed()) {
            try {
                if (source.isEnabled(tenantDomain)) {
                    enabled.add(source);
                }
            } catch (Throwable t) {
                LOG.error("Breach source '" + id(source) + "' failed to report whether it is enabled. "
                        + "It will not be consulted.", t);
            }
        }
        return enabled;
    }

    private Decision check(BreachSource source, Credential credential, String tenantDomain) {

        try {
            Decision decision = source.check(credential, tenantDomain);
            if (decision == null) {
                LOG.error("Breach source '" + id(source) + "' returned no decision. It is treated as accept.");
                return Decision.ACCEPT;
            }
            return decision;
        } catch (Throwable t) {
            // Contained so that a defect in one connector does not affect the others.
            LOG.error("Breach source '" + id(source) + "' failed while checking a password. It is treated as "
                    + "accept and the remaining sources still run.", t);
            return Decision.ACCEPT;
        }
    }

    private static String id(BreachSource source) {

        try {
            return source.getId();
        } catch (Throwable t) {
            return "unknown";
        }
    }
}
