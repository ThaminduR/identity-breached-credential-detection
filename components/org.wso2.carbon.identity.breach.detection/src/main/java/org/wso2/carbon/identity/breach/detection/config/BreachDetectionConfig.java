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

package org.wso2.carbon.identity.breach.detection.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.breach.detection.constants.BreachDetectionConstants;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Deployment settings for breached credential detection, read once from the properties of this
 * listener's own {@code [[event_listener]]} entry in deployment.toml. Changing them needs a restart.
 */
public class BreachDetectionConfig {

    private static final Log LOG = LogFactory.getLog(BreachDetectionConfig.class);

    // A literal, because naming the listener class here would create a package cycle.
    private static final String LISTENER_CLASS =
            "org.wso2.carbon.identity.breach.detection.listener.BreachDetectionListener";

    private final boolean enabledAtDeployment;
    private final int listenerOrder;
    private final Map<String, Map<String, String>> sourceProperties;

    public BreachDetectionConfig() {

        IdentityEventListenerConfig listenerConfig = IdentityUtil.readEventListenerProperty(
                UserOperationEventListener.class.getName(), LISTENER_CLASS);

        this.enabledAtDeployment = listenerConfig != null && Boolean.parseBoolean(listenerConfig.getEnable());
        this.listenerOrder = listenerConfig == null
                ? BreachDetectionConstants.DEFAULT_LISTENER_ORDER : listenerConfig.getOrder();

        this.sourceProperties = Collections.unmodifiableMap(
                parse(listenerConfig == null ? null : listenerConfig.getProperties()));
    }

    public boolean isEnabledAtDeployment() {

        return enabledAtDeployment;
    }

    public int getListenerOrder() {

        return listenerOrder;
    }

    public SourceConfiguration getSourceConfiguration(String sourceId) {

        return new ResolvedSourceConfiguration(sourceId, sourceProperties.get(sourceId));
    }

    private static Map<String, Map<String, String>> parse(Properties properties) {

        Map<String, Map<String, String>> sources = new LinkedHashMap<>();
        if (properties == null) {
            return sources;
        }
        String prefix = BreachDetectionConstants.SOURCE_PROPERTY_PREFIX;
        for (String key : properties.stringPropertyNames()) {
            if (!key.startsWith(prefix)) {
                warnUnrecognised(key);
                continue;
            }
            String remainder = key.substring(prefix.length());
            int separator = remainder.indexOf('.');
            if (separator < 1 || separator == remainder.length() - 1) {
                warnUnrecognised(key);
                continue;
            }
            sources.computeIfAbsent(remainder.substring(0, separator), id -> new LinkedHashMap<>())
                    .put(remainder.substring(separator + 1), properties.getProperty(key));
        }
        return sources;
    }

    private static void warnUnrecognised(String key) {

        LOG.warn("Ignoring the breach detection listener property '" + key + "'. Properties must be named "
                + BreachDetectionConstants.SOURCE_PROPERTY_PREFIX + "<source id>.<property>, and the key "
                + "must be quoted in deployment.toml, for example: properties.\""
                + BreachDetectionConstants.SOURCE_PROPERTY_PREFIX
                + BreachDetectionConstants.LOCAL_LIST_SOURCE_ID + ".enable\" = true");
    }
}
