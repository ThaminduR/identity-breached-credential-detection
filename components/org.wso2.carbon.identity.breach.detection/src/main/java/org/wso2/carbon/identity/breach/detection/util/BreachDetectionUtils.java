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

package org.wso2.carbon.identity.breach.detection.util;

import org.wso2.carbon.identity.breach.detection.constants.BreachDetectionConstants;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/** Helpers shared across the bundle. No method here accepts a candidate password. */
public class BreachDetectionUtils {

    private BreachDetectionUtils() {

    }

    /** Falls back to the supplied default, so a missing translation never shows the key to a user. */
    public static String getMessage(String key, String defaultMessage) {

        try {
            ResourceBundle bundle = ResourceBundle.getBundle(BreachDetectionConstants.RESOURCE_BUNDLE,
                    Locale.getDefault(), BreachDetectionUtils.class.getClassLoader());
            if (bundle.containsKey(key)) {
                return bundle.getString(key);
            }
        } catch (MissingResourceException ignored) {
            // The resource bundle is optional. The supplied default is what the caller relies on.
        }
        return defaultMessage;
    }

    /** @param fallback used when unset or unparseable. */
    public static int parseInt(String value, int fallback) {

        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    /** @param fallback used when unset. */
    public static boolean parseBoolean(String value, boolean fallback) {

        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        return Boolean.parseBoolean(value.trim());
    }
}
