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
 * Names shared across the capability. Exported so a caller can name the same error codes without
 * duplicating literals.
 */
public class BreachDetectionConstants {

    private BreachDetectionConstants() {

    }

    /** After input validation at 3 and before the service extension at 10000. */
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
     * The refusals a user can see. Each pairs a code with English text, the same shape the password policy
     * connector uses. A client localizes on the code; the text is the fallback when it does not.
     */
    public enum ErrorMessages {

        ERROR_CODE_BREACHED_PASSWORD("BRD-60001",
                "This password has appeared in a known data breach. Choose a longer, unique password."),
        ERROR_CODE_CANNOT_VERIFY("BRD-60002",
                "This password could not be checked right now. Try again in a moment.");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + " - " + message;
        }
    }
}
