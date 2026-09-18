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
import org.wso2.carbon.identity.breach.detection.engine.BreachEvaluationEngine;
import org.wso2.carbon.identity.breach.detection.listener.BreachDetectionListener;
import org.wso2.carbon.identity.breach.detection.source.LocalBlocklistSource;
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;

import java.util.ArrayList;
import java.util.List;

/**
 * Breached credential detection service component. The {@link BreachSource} reference is dynamic and
 * has multiple cardinality, so a connector binds and unbinds on its own.
 */
@Component(
        name = "identity.breach.detection.component",
        immediate = true
)
public class BreachDetectionServiceComponent {

    private static final Log LOG = LogFactory.getLog(BreachDetectionServiceComponent.class);

    private final List<ServiceRegistration<?>> registrations = new ArrayList<>();

    private volatile BreachDetectionConfig config;

    private LocalBlocklistSource localBlocklistSource;

    @Activate
    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();
        BreachDetectionDataHolder holder = BreachDetectionDataHolder.getInstance();

        config = new BreachDetectionConfig();

        holder.setEvaluationEngine(new BreachEvaluationEngine());

        // Sources bound before activation are configured here, later ones by the bind callback, so
        // neither is configured twice.
        for (BreachSource source : holder.getSources()) {
            configure(source);
        }

        localBlocklistSource = new LocalBlocklistSource();
        registrations.add(bundleContext.registerService(BreachSource.class, localBlocklistSource, null));

        // Last, so no credential write can reach the listener before the sources are ready.
        registrations.add(bundleContext.registerService(UserOperationEventListener.class,
                new BreachDetectionListener(config), null));

        LOG.info("Breached password detection started. Deployment switch: "
                + (config.isEnabledAtDeployment() ? "on" : "off")
                + ", listener order: " + config.getListenerOrder() + ".");
    }

    private void configure(BreachSource source) {

        try {
            source.configure(config.getSourceConfiguration(source.getId()));
        } catch (Throwable t) {
            // Throwable, because a connector built against another contract version fails with a linkage Error.
            LOG.error("Failed to configure breach source '" + source.getId()
                    + "'. It keeps whatever configuration it already had.", t);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        for (ServiceRegistration<?> registration : registrations) {
            try {
                registration.unregister();
            } catch (IllegalStateException e) {
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

        BreachDetectionDataHolder.getInstance().bindSource(source);
        if (config != null) {
            configure(source);
        }
    }

    protected void unsetBreachSource(BreachSource source) {

        BreachDetectionDataHolder.getInstance().unbindSource(source);
    }

    @Reference(
            name = "identity.core.init.event.service",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent event) {

    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent event) {

    }
}
