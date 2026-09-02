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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.breach.detection.config.BreachDetectionConfig;
import org.wso2.carbon.identity.breach.detection.config.ResolvedSourceConfiguration;
import org.wso2.carbon.identity.breach.detection.engine.BreachEvaluationEngine;
import org.wso2.carbon.identity.breach.detection.engine.SourceRegistry;
import org.wso2.carbon.identity.breach.detection.listener.BreachDetectionListener;
import org.wso2.carbon.identity.breach.detection.source.LocalBlocklistSource;
import org.wso2.carbon.identity.breach.source.BreachSource;
import org.wso2.carbon.identity.breach.detection.util.BreachDetectionUtils;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Starts the capability and publishes its services.
 * <p>
 * The reference to {@link BreachSource} is dynamic and multiple-cardinality, which is the whole point of the
 * core/connector split: a connector JAR dropped into {@code dropins} registers itself and is picked up with no
 * configuration edit and no restart - a service event rather than a file change - and removing it unbinds one
 * service and changes nothing else.
 */
@Component(
        name = "identity.breach.detection.component",
        immediate = true
)
public class BreachDetectionServiceComponent {

    private static final Log LOG = LogFactory.getLog(BreachDetectionServiceComponent.class);

    private final List<ServiceRegistration<?>> registrations = new ArrayList<>();

    @Activate
    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();
        BreachDetectionDataHolder holder = BreachDetectionDataHolder.getInstance();
        SourceRegistry registry = holder.getSourceRegistry();

        BreachDetectionConfig config = BreachDetectionConfig.reload();

        holder.setEvaluationEngine(new BreachEvaluationEngine(registry, config.getWorkerThreads(),
                config.getEvaluationTimeoutMs()));

        LocalBlocklistSource localBlocklistSource = new LocalBlocklistSource();
        holder.setLocalBlocklistSource(localBlocklistSource);

        // The in-tree offline list registers exactly like a connector, which is also what configures it: the
        // bind callback below fires for it too. The engine has no special path for it.
        registrations.add(bundleContext.registerService(BreachSource.class, localBlocklistSource, null));
        registrations.add(bundleContext.registerService(UserOperationEventListener.class,
                new BreachDetectionListener(), null));

        // Re-applied after the reload above, since a source may have bound before this component activated.
        for (BreachSource source : registry.installed()) {
            configure(source);
        }

        LOG.info("Breached password detection started. Deployment switch: "
                + (config.isEnabledAtDeployment() ? "on" : "off")
                + ", listener order: " + config.getListenerOrder()
                + ", per-source timeout: " + config.getEvaluationTimeoutMs() + " ms"
                + ", bound sources: " + registry.describe() + ".");

        List<String> orphaned = new ArrayList<>();
        for (Map.Entry<String, Map<String, String>> entry : config.getSourceProperties().entrySet()) {
            if (!registry.get(entry.getKey()).isPresent()) {
                orphaned.add(entry.getKey());
            }
        }
        if (!orphaned.isEmpty()) {
            // Reported rather than ignored: it usually means a connector JAR is missing, which is a deployment
            // action rather than a configuration one.
            LOG.warn("Breach detection configuration names sources that are not installed: " + orphaned
                    + ". Add the connector JARs to repository/components/dropins, or remove the configuration.");
        }
    }

    /**
     * Hand a source the settings it declared, resolved from operator configuration.
     * <p>
     * The only place a source's configuration is assembled. A connector reads nothing itself and receives no
     * filesystem or vault access of its own, which is what makes the {@code secret} flag on a property
     * descriptor enforceable. Contained: a connector that cannot be configured must not stop the others
     * starting.
     */
    private static void configure(BreachSource source) {

        try {
            Map<String, String> configured = BreachDetectionConfig.getInstance()
                    .getSourceProperties(BreachDetectionUtils.normalizeSourceId(source.getId()));
            source.configure(new ResolvedSourceConfiguration(source.getId(), source.getProperties(), configured));
        } catch (Throwable t) {
            LOG.error("Failed to configure breach source '" + source.getId()
                    + "'. It will report itself as not configured.", t);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        for (ServiceRegistration<?> registration : registrations) {
            try {
                registration.unregister();
            } catch (Exception e) {
                LOG.debug("Failed to unregister a breach detection service.", e);
            }
        }
        registrations.clear();

        BreachDetectionDataHolder holder = BreachDetectionDataHolder.getInstance();
        if (holder.getEvaluationEngine() != null) {
            holder.getEvaluationEngine().shutdown();
        }
        if (holder.getLocalBlocklistSource() != null) {
            holder.getLocalBlocklistSource().shutdown();
        }
        LOG.info("Breached password detection stopped.");
    }

    @Reference(
            name = "breach.source",
            service = BreachSource.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetBreachSource"
    )
    protected void setBreachSource(BreachSource source) {

        BreachDetectionDataHolder.getInstance().getSourceRegistry().bind(source);
        configure(source);
    }

    protected void unsetBreachSource(BreachSource source) {

        BreachDetectionDataHolder.getInstance().getSourceRegistry().unbind(source);
    }


    /**
     * Held so that identity.xml has been parsed before this component reads it.
     */
    @Reference(
            name = "identity.core.init.event.service",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent event) {

        // Nothing to hold; the reference exists purely for start-up ordering.
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent event) {

        // Nothing to release.
    }
}
