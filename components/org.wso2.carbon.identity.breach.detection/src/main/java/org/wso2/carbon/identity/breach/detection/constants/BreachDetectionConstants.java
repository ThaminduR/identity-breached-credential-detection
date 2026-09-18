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
 * Breached credential detection constants.
 */
public class BreachDetectionConstants {

    private BreachDetectionConstants() {

    }

    public static final int DEFAULT_LISTENER_ORDER = 420;

    public static final String SOURCE_PROPERTY_PREFIX = "sources.";

    public static final String LOCAL_LIST_SOURCE_ID = "localList";

    private static final String ERROR_PREFIX = "BRD-";

    public enum ErrorMessages {

        ERROR_CODE_BREACHED_PASSWORD("60001",
                "This password has appeared in a known data breach. Choose a longer, unique password."),
        ERROR_CODE_CANNOT_VERIFY("60002",
                "This password could not be checked right now. Try again in a moment.");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return ERROR_PREFIX + code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return getCode() + " - " + message;
        }
    }
}
