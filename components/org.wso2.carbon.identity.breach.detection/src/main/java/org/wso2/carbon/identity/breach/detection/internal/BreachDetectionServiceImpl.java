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

package org.wso2.carbon.identity.breach.detection.internal;

import org.wso2.carbon.identity.breach.detection.config.BreachDetectionConfig;
import org.wso2.carbon.identity.breach.detection.engine.SourceRegistry;
import org.wso2.carbon.identity.breach.detection.mgt.BreachDetectionService;
import org.wso2.carbon.identity.breach.detection.mgt.BreachDetectionStatus;
import org.wso2.carbon.identity.breach.detection.mgt.EnforcementStatus;
import org.wso2.carbon.identity.breach.detection.mgt.SourceReport;
import org.wso2.carbon.identity.breach.detection.source.LocalBlocklistSource;
import org.wso2.carbon.identity.breach.source.BreachSource;
import org.wso2.carbon.identity.breach.source.FailureAction;
import org.wso2.carbon.identity.breach.source.SourceStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Assembles what an administrator sees.
 * <p>
 * Every source owns its own enablement and its own configuration surface, so this reports what the bound
 * sources say about themselves rather than reading a central policy. A source that is not installed cannot
 * appear at all, which is why there is no notion here of a source being named but missing.
 */
public class BreachDetectionServiceImpl implements BreachDetectionService {

    @Override
    public BreachDetectionStatus getStatus(String tenantDomain) {

        BreachDetectionDataHolder holder = BreachDetectionDataHolder.getInstance();
        SourceRegistry registry = holder.getSourceRegistry();
        BreachDetectionConfig config = BreachDetectionConfig.getInstance();

        List<SourceReport> reports = new ArrayList<>();
        int enabledCount = 0;
        int readyCount = 0;

        for (BreachSource source : registry.installed()) {
            SourceReport report = report(source, tenantDomain);
            reports.add(report);
            if (report.isEnabled()) {
                enabledCount++;
                if (report.getStatus().getState() == SourceStatus.State.READY) {
                    readyCount++;
                }
            }
        }

        return new BreachDetectionStatus(tenantDomain, config.isEnabledAtDeployment(), enabledCount > 0,
                resolveStatus(config, enabledCount, readyCount), reports,
                SourceConfigurator.orphanedNamespaces(registry));
    }

    @Override
    public String reloadSources() {

        BreachDetectionConfig.reload();
        BreachDetectionDataHolder holder = BreachDetectionDataHolder.getInstance();
        SourceRegistry registry = holder.getSourceRegistry();
        SourceConfigurator.configureAll(registry);
        LocalBlocklistSource localList = holder.getLocalBlocklistSource();

        return "Reconfigured " + registry.installed().size() + " bound sources. "
                + (localList == null ? "No local blocklist source is present." : localList.reload());
    }

    private EnforcementStatus resolveStatus(BreachDetectionConfig config, int enabledCount, int readyCount) {

        if (!config.isEnabledAtDeployment()) {
            return EnforcementStatus.DISABLED;
        }
        if (enabledCount == 0) {
            return EnforcementStatus.OFF;
        }
        if (readyCount == 0) {
            // Every source this organization switched on is currently unable to answer.
            return EnforcementStatus.NOT_ENFORCING;
        }

        return readyCount == enabledCount ? EnforcementStatus.ENFORCING : EnforcementStatus.DEGRADED;
    }

    /**
     * A source is asked about itself here, and every one of those answers is a call into a connector. Each is
     * contained: a connector that throws while describing itself must not take the whole administrator view
     * down with it.
     */
    private SourceReport report(BreachSource source, String tenantDomain) {

        boolean enabled = false;
        try {
            enabled = source.isEnabled(tenantDomain);
        } catch (Throwable t) {
            // Left as not enabled: a source that cannot say must not be reported as consulted.
        }

        SourceStatus status;
        try {
            status = source.getStatus(tenantDomain);
        } catch (Throwable t) {
            status = SourceStatus.builder(SourceStatus.State.UNAVAILABLE)
                    .summary("The source failed to report its status.")
                    .build();
        }

        FailureAction failureAction;
        try {
            failureAction = source.getFailureAction(tenantDomain);
        } catch (Throwable t) {
            failureAction = FailureAction.ALLOW;
        }

        return new SourceReport(source.getId(), enabled, source.getPriority(), source.getDescriptor(), status,
                source.getCapabilities(), source.getProperties(), failureAction,
                BreachDetectionDataHolder.getInstance().getMetrics().snapshot(tenantDomain, source.getId()));
    }
}
