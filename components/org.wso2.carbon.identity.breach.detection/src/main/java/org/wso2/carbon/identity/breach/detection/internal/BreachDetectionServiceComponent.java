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
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Starts the capability and publishes its services. The {@link BreachSource} reference is dynamic and has
 * multiple cardinality, so a connector binds and unbinds on its own.
 */
@Component(
        name = "identity.breach.detection.component",
        immediate = true
)
public class BreachDetectionServiceComponent {

    private static final Log LOG = LogFactory.getLog(BreachDetectionServiceComponent.class);

    private final List<ServiceRegistration<?>> registrations = new ArrayList<>();

    /**
     * Null until activation. SCR binds sources before the configuration is read, so a source bound early is
     * configured by the activation loop and one bound later by its own callback, never both.
     */
    private volatile BreachDetectionConfig config;

    private LocalBlocklistSource localBlocklistSource;

    @Activate
    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();
        BreachDetectionDataHolder holder = BreachDetectionDataHolder.getInstance();
        SourceRegistry registry = holder.getSourceRegistry();

        config = new BreachDetectionConfig();

        holder.setEvaluationEngine(new BreachEvaluationEngine(registry));

        localBlocklistSource = new LocalBlocklistSource();

        // The local list registers as an OSGi service in the same way a connector does, so the bind
        // callback below configures it too.
        registrations.add(bundleContext.registerService(BreachSource.class, localBlocklistSource, null));
        registrations.add(bundleContext.registerService(UserOperationEventListener.class,
                new BreachDetectionListener(config), null));

        for (BreachSource source : registry.installed()) {
            configure(source);
        }

        LOG.info("Breached password detection started. Deployment switch: "
                + (config.isEnabledAtDeployment() ? "on" : "off")
                + ", listener order: " + config.getListenerOrder() + ".");
    }

    /** Contained, so one connector's failure cannot stop the others from starting. */
    private void configure(BreachSource source) {

        try {
            Map<String, String> configured = config.getSourceProperties(source.getId());
            source.configure(new ResolvedSourceConfiguration(source.getId(), configured));
        } catch (Throwable t) {
            LOG.error("Failed to configure breach source '" + source.getId()
                    + "'. It keeps whatever configuration it already had.", t);
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
        config = null;

        if (localBlocklistSource != null) {
            localBlocklistSource.shutdown();
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
        if (config != null) {
            configure(source);
        }
    }

    protected void unsetBreachSource(BreachSource source) {

        BreachDetectionDataHolder.getInstance().getSourceRegistry().unbind(source);
    }

    /** Referenced so that identity.xml is parsed before this component reads it. */
    @Reference(
            name = "identity.core.init.event.service",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent event) {

        // The reference exists only to order start-up.
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent event) {

        // Nothing to release.
    }
}
