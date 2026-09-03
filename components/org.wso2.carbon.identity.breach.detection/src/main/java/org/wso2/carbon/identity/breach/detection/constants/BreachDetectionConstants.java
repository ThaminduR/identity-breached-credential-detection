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

package org.wso2.carbon.identity.breach.detection.constants;

/**
 * Names shared across the capability: configuration keys, governance property names, and the error codes a
 * caller sees. Exported so an administrator API can name the same things without duplicating literals.
 */
public class BreachDetectionConstants {

    private BreachDetectionConstants() {

    }

    /**
     * Placed after input validation at 3, so a password that fails composition rules never reaches a breach
     * source, and before the service extension at 10000, so in-product policy resolves before a customer
     * extension runs.
     */
    public static final int DEFAULT_LISTENER_ORDER = 420;

    /** The identity.xml element carrying operator configuration, rendered from [breach_detection]. */
    public static final String CONFIG_ELEMENT = "BreachDetection";
    public static final String CONFIG_SOURCES_ELEMENT = "Sources";
    public static final String CONFIG_SOURCE_ELEMENT = "Source";
    public static final String CONFIG_PROPERTY_ELEMENT = "Property";
    public static final String CONFIG_ATTRIBUTE_ID = "id";
    public static final String CONFIG_ATTRIBUTE_NAME = "name";
    public static final String CONFIG_ATTRIBUTE_SECRET_ALIAS = "secretAlias";

    /** The source that ships in this bundle. */
    public static final String LOCAL_LIST_SOURCE_ID = "localList";


    /**
     * Error codes. A policy rejection is reported as a client error carrying the reason. It is not reported
     * as a server fault, because a server fault cannot be distinguished from an outage and leaves a portal
     * with nothing to display.
     */
    public static final String ERROR_CODE_BREACHED_PASSWORD = "BRD-60001";
    public static final String ERROR_CODE_CANNOT_VERIFY = "BRD-60002";

    /** Message keys, resolved through the bundled resource bundle so that they localize with the product. */
    public static final String MESSAGE_KEY_BREACHED = "breach.detection.password.breached";
    public static final String MESSAGE_KEY_CANNOT_VERIFY = "breach.detection.password.unverifiable";

    public static final String RESOURCE_BUNDLE = "org.wso2.carbon.identity.breach.detection.i18n.Resources";
}
