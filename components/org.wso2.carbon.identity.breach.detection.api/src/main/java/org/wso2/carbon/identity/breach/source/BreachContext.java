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

/**
 * What a source is given to reach a verdict: the candidate password, and the organization it is being set in.
 * <p>
 * A builder rather than a constructor so the context can gain fields - a subject, the kind of operation - as
 * something needs them, without breaking a connector compiled against an earlier revision.
 */
public final class BreachContext {

    private final Credential credential;
    private final String tenantDomain;

    private BreachContext(Builder builder) {

        this.credential = builder.credential;
        this.tenantDomain = builder.tenantDomain;
    }

    public Credential getCredential() {

        return credential;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public static Builder builder() {

        return new Builder();
    }

    /**
     * Builder for {@link BreachContext}.
     */
    public static final class Builder {

        private Credential credential;
        private String tenantDomain;

        private Builder() {

        }

        public Builder credential(Credential credential) {

            this.credential = credential;
            return this;
        }

        public Builder tenantDomain(String tenantDomain) {

            this.tenantDomain = tenantDomain;
            return this;
        }

        public BreachContext build() {

            return new BreachContext(this);
        }
    }
}
