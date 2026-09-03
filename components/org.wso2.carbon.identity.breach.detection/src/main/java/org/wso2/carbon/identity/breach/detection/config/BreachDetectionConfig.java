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
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Operator configuration: the deployment switch, the evaluation bounds, and the per-source namespaces.
 * <p>
 * Read from identity.xml, which the config parser renders from {@code [breach_detection]} in deployment.toml.
 * This configuration is kept separate from tenant policy for two reasons. Switching the feature off must work
 * when the tenant configuration store is unreachable, and a filesystem path or a memory limit is a property
 * of the deployment rather than of a tenant.
 */
public class BreachDetectionConfig {

    private static final Log LOG = LogFactory.getLog(BreachDetectionConfig.class);

    private static volatile BreachDetectionConfig instance;

    // The listener's own name, as declared in identity.xml. Held as a string because reading it from
    // BreachDetectionListener would make this package depend on the package that depends on it.
    private static final String LISTENER_CLASS =
            "org.wso2.carbon.identity.breach.detection.listener.BreachDetectionListener";

    private final boolean enabledAtDeployment;
    private final int listenerOrder;
    private final Map<String, String> globalProperties;
    private final Map<String, Map<String, String>> sourceProperties;

    private BreachDetectionConfig() {

        IdentityEventListenerConfig listenerConfig = IdentityUtil.readEventListenerProperty(
                UserOperationEventListener.class.getName(), LISTENER_CLASS);

        // A missing declaration means the listener was never wired in, so the switch reads as off.
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
     * Reports the value of the listener's {@code enable} attribute. Enforcement of that attribute belongs to
     * Carbon, which skips a disabled listener before it is called, so this value is read only for logging.
     *
     * @return whether the listener is declared enabled.
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
     * Bulk imports and migration-time writes can be exempted, so that a migration does not make one network
     * call per row or consume third-party quota for data that is already in the store.
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

        SecretResolver resolver = secretResolver(root);

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
                        parseSource(source, sources, resolver);
                    }
                }
            }
        }
    }

    private void parseSource(OMElement sourceElement, Map<String, Map<String, String>> sources,
                             SecretResolver resolver) {

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
            // An alias that cannot be resolved leaves the property absent. The alias text is not stored.
            properties.put(name, alias == null ? value : resolveSecret(resolver, alias));
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

    /**
     * Returns a resolver over the document root, or null when the secure vault is unavailable. Without a
     * resolver a secret value is read literally, so one unavailable vault does not fail the whole
     * configuration layer.
     */
    private static SecretResolver secretResolver(OMElement element) {

        try {
            OMContainer parent = element.getParent();
            OMElement documentRoot = element;
            while (parent instanceof OMElement) {
                documentRoot = (OMElement) parent;
                parent = documentRoot.getParent();
            }
            return SecretResolverFactory.create(documentRoot, false);
        } catch (Throwable t) {
            LOG.debug("Secure vault support is unavailable for breach detection configuration.", t);
            return null;
        }
    }

    /**
     * @return the resolved value, or null. A vault failure is logged without the alias or the value.
     */
    private static String resolveSecret(SecretResolver resolver, String alias) {

        if (resolver == null || !resolver.isInitialized()) {
            return null;
        }
        try {
            return resolver.isTokenProtected(alias) ? resolver.resolve(alias) : null;
        } catch (Throwable t) {
            LOG.error("Failed to resolve a secure vault alias for a breach detection source property.");
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
