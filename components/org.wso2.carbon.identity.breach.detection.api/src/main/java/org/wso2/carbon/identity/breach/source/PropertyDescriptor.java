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

package org.wso2.carbon.identity.breach.source;

import java.util.Optional;

/**
 * One deployment setting a source needs.
 * <p>
 * The connector declares its settings and the core resolves the values, so the connector reads no file and
 * holds no vault handle. That is what makes {@link #isSecret()} enforceable by the core.
 */
public final class PropertyDescriptor {

    private final String name;
    private final boolean required;
    private final boolean secret;
    private final String defaultValue;

    private PropertyDescriptor(String name, boolean required, boolean secret, String defaultValue) {

        this.name = name;
        this.required = required;
        this.secret = secret;
        this.defaultValue = defaultValue;
    }

    /**
     * @param name the setting name.
     * @return a setting the source cannot work without. Reported at load when it is missing.
     */
    public static PropertyDescriptor required(String name) {

        return new PropertyDescriptor(name, true, false, null);
    }

    /**
     * @param name         the setting name.
     * @param defaultValue the value used when the operator configures none.
     * @return an optional setting.
     */
    public static PropertyDescriptor optional(String name, String defaultValue) {

        return new PropertyDescriptor(name, false, false, defaultValue);
    }

    /**
     * @param name the setting name.
     * @return a credential, reachable only through {@link SourceConfiguration#getSecret(String)}.
     */
    public static PropertyDescriptor secret(String name) {

        return new PropertyDescriptor(name, false, true, null);
    }

    public String getName() {

        return name;
    }

    public boolean isRequired() {

        return required;
    }

    public boolean isSecret() {

        return secret;
    }

    public Optional<String> getDefaultValue() {

        return Optional.ofNullable(defaultValue);
    }
}
