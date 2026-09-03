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
 * holds no vault handle. That is what makes the {@code secret} flag enforceable by the core.
 */
public final class PropertyDescriptor {

    private final String name;
    private final boolean required;
    private final boolean secret;
    private final String defaultValue;

    private PropertyDescriptor(Builder builder) {

        this.name = builder.name;
        this.required = builder.required;
        this.secret = builder.secret;
        this.defaultValue = builder.defaultValue;
    }

    /**
     * @return the setting name, as it appears under {@code [breach_detection.sources.&lt;id&gt;]}.
     */
    public String getName() {

        return name;
    }

    /**
     * @return {@code true} if the source cannot work without it. Reported at load when it is missing.
     */
    public boolean isRequired() {

        return required;
    }

    /**
     * @return {@code true} if the value is a credential: vault-resolved, never returned, never logged.
     */
    public boolean isSecret() {

        return secret;
    }

    public Optional<String> getDefaultValue() {

        return Optional.ofNullable(defaultValue);
    }

    public static Builder builder(String name) {

        return new Builder(name);
    }

    /**
     * Builder for {@link PropertyDescriptor}.
     */
    public static final class Builder {

        private final String name;
        private boolean required;
        private boolean secret;
        private String defaultValue;

        private Builder(String name) {

            this.name = name;
        }

        public Builder required(boolean required) {

            this.required = required;
            return this;
        }

        public Builder secret(boolean secret) {

            this.secret = secret;
            return this;
        }

        public Builder defaultValue(String defaultValue) {

            this.defaultValue = defaultValue;
            return this;
        }

        public PropertyDescriptor build() {

            return new PropertyDescriptor(this);
        }
    }
}
