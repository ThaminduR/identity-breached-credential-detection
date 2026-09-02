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

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMContainer;
import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.breach.detection.constants.BreachDetectionConstants;
import org.wso2.carbon.identity.breach.detection.util.BreachDetectionUtils;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Operator configuration: the deployment kill switch, the evaluation bounds, and the per-source namespaces.
 * <p>
 * Read from identity.xml, which the config parser renders from {@code [breach_detection]} in deployment.toml.
 * Deliberately separate from tenant policy: incident control must not depend on a tenant configuration store
 * being reachable, and filesystem and memory are deployment properties rather than tenant ones.
 */
public class BreachDetectionConfig {

    private static final Log LOG = LogFactory.getLog(BreachDetectionConfig.class);

    private static volatile BreachDetectionConfig instance;

    private final boolean enabledAtDeployment;
    private final int listenerOrder;
    private final Map<String, String> globalProperties;
    private final Map<String, Map<String, String>> sourceProperties;

    private BreachDetectionConfig() {

        IdentityEventListenerConfig listenerConfig = IdentityUtil.readEventListenerProperty(
                BreachDetectionConstants.LISTENER_TYPE, BreachDetectionConstants.LISTENER_CLASS);

        // Absent declaration means the capability was never wired in, which is off, not on.
        this.enabledAtDeployment = listenerConfig != null && Boolean.parseBoolean(listenerConfig.getEnable());
        this.listenerOrder = listenerConfig == null
                ? BreachDetectionConstants.DEFAULT_LISTENER_ORDER : listenerConfig.getOrder();

        Map<String, String> globals = new LinkedHashMap<>();
        Map<String, Map<String, String>> sources = new LinkedHashMap<>();
        parse(globals, sources);
        this.globalProperties = Collections.unmodifiableMap(globals);
        this.sourceProperties = Collections.unmodifiableMap(sources);
    }

    public static BreachDetectionConfig getInstance() {

        BreachDetectionConfig local = instance;
        if (local == null) {
            synchronized (BreachDetectionConfig.class) {
                local = instance;
                if (local == null) {
                    local = new BreachDetectionConfig();
                    instance = local;
                }
            }
        }
        return local;
    }

    /**
     * Re-read identity.xml. Used by the management service after an operator edits configuration.
     *
     * @return the reloaded configuration.
     */
    public static BreachDetectionConfig reload() {

        synchronized (BreachDetectionConfig.class) {
            instance = new BreachDetectionConfig();
            return instance;
        }
    }

    /**
     * The deployment kill switch. False disables the capability for every tenant without removing software,
     * and leaves stored tenant policy untouched for when it is switched back on.
     *
     * @return whether the capability is switched on at deployment level.
     */
    public boolean isEnabledAtDeployment() {

        return enabledAtDeployment;
    }

    public int getListenerOrder() {

        return listenerOrder;
    }

    /**
     * @return the configured settings for every source namespace, keyed by normalized source id, with any
     * {@code $secret{alias}} reference already resolved.
     */
    public Map<String, Map<String, String>> getSourceProperties() {

        return sourceProperties;
    }

    /**
     * @param normalizedSourceId key from {@link BreachDetectionUtils#normalizeSourceId(String)}.
     * @return the settings written under that namespace, or {@code null} if the operator configured none.
     */
    public Map<String, String> getSourceProperties(String normalizedSourceId) {

        return sourceProperties.get(normalizedSourceId);
    }

    public int getEvaluationTimeoutMs() {

        return BreachDetectionUtils.parseInt(globalProperties.get(BreachDetectionConstants.CONFIG_SOURCE_TIMEOUT_MS),
                BreachDetectionConstants.DEFAULT_SOURCE_TIMEOUT_MS);
    }

    /**
     * Bulk imports and migration-time writes can be exempted so a migration does not pay a network round trip
     * per row, or burn third-party quota on data that is already in the store.
     *
     * @return whether bulk operations skip evaluation.
     */
    public boolean isBulkExempt() {

        return BreachDetectionUtils.parseBoolean(globalProperties.get(BreachDetectionConstants.CONFIG_EXEMPT_BULK),
                false);
    }

    public int getWorkerThreads() {

        return BreachDetectionUtils.parseInt(globalProperties.get(BreachDetectionConstants.CONFIG_WORKER_THREADS),
                BreachDetectionConstants.DEFAULT_WORKER_THREADS);
    }

    private void parse(Map<String, String> globals, Map<String, Map<String, String>> sources) {

        OMElement root;
        try {
            root = IdentityConfigParser.getInstance()
                    .getConfigElement(BreachDetectionConstants.CONFIG_ELEMENT);
        } catch (Throwable t) {
            LOG.error("Could not read the " + BreachDetectionConstants.CONFIG_ELEMENT
                    + " configuration element. Breach detection will run with defaults.", t);
            return;
        }
        if (root == null) {
            return;
        }

        SecretResolutionSupport secrets = createSecretSupport(root);

        for (OMElement element : children(root)) {
            String localName = element.getLocalName();
            if (BreachDetectionConstants.CONFIG_PROPERTY_ELEMENT.equals(localName)) {
                String name = attribute(element, BreachDetectionConstants.CONFIG_ATTRIBUTE_NAME);
                if (name != null) {
                    globals.put(name, text(element));
                }
            } else if (BreachDetectionConstants.CONFIG_SOURCES_ELEMENT.equals(localName)) {
                for (OMElement source : children(element)) {
                    if (BreachDetectionConstants.CONFIG_SOURCE_ELEMENT.equals(source.getLocalName())) {
                        parseSource(source, sources, secrets);
                    }
                }
            }
        }
    }

    private void parseSource(OMElement sourceElement, Map<String, Map<String, String>> sources,
                             SecretResolutionSupport secrets) {

        String id = attribute(sourceElement, BreachDetectionConstants.CONFIG_ATTRIBUTE_ID);
        if (id == null || id.trim().isEmpty()) {
            LOG.warn("Ignoring a breach detection source configuration block with no id attribute.");
            return;
        }
        id = id.trim();
        Map<String, String> properties = new LinkedHashMap<>();
        for (OMElement property : children(sourceElement)) {
            if (!BreachDetectionConstants.CONFIG_PROPERTY_ELEMENT.equals(property.getLocalName())) {
                continue;
            }
            String name = attribute(property, BreachDetectionConstants.CONFIG_ATTRIBUTE_NAME);
            if (name == null) {
                continue;
            }
            String value = text(property);
            String alias = attribute(property, BreachDetectionConstants.CONFIG_ATTRIBUTE_SECRET_ALIAS);
            if (alias == null) {
                alias = secretAliasFromValue(value);
            }
            // A secret that could not be resolved stays absent rather than being stored as its own alias.
            properties.put(name, alias == null ? value : (secrets == null ? null : secrets.resolve(alias)));
        }
        sources.put(BreachDetectionUtils.normalizeSourceId(id), properties);
    }

    /**
     * The element children of a configuration element, skipping comments and text nodes.
     */
    private static List<OMElement> children(OMElement element) {

        List<OMElement> elements = new ArrayList<>();
        for (Iterator<?> it = element.getChildElements(); it.hasNext(); ) {
            Object child = it.next();
            if (child instanceof OMElement) {
                elements.add((OMElement) child);
            }
        }
        return elements;
    }

    private SecretResolutionSupport createSecretSupport(OMElement element) {

        try {
            OMContainer parent = element.getParent();
            OMElement documentRoot = element;
            while (parent instanceof OMElement) {
                documentRoot = (OMElement) parent;
                parent = documentRoot.getParent();
            }
            return new SecretResolutionSupport(documentRoot);
        } catch (Throwable t) {
            LOG.debug("Secure vault support is unavailable for breach detection configuration.", t);
            return null;
        }
    }

    private static String secretAliasFromValue(String value) {

        if (value != null && value.startsWith("$secret{") && value.endsWith("}")) {
            return value.substring("$secret{".length(), value.length() - 1);
        }
        return null;
    }

    private static String attribute(OMElement element, String name) {

        for (Iterator<?> it = element.getAllAttributes(); it.hasNext(); ) {
            Object next = it.next();
            if (next instanceof OMAttribute && name.equals(((OMAttribute) next).getLocalName())) {
                return ((OMAttribute) next).getAttributeValue();
            }
        }
        return null;
    }

    private static String text(OMElement element) {

        String value = element.getText();
        return value == null ? null : value.trim();
    }
}
