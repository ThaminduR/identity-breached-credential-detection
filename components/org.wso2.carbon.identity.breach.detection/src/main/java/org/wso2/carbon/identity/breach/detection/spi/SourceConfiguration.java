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

package org.wso2.carbon.identity.breach.detection.spi;

import java.util.Optional;

/**
 * The resolved deployment settings for one source. A source reads no configuration file and resolves no
 * secret alias. Each accessor takes the fallback to use when the setting is absent.
 */
public interface SourceConfiguration {

    /** @return the configured value, or empty when unset or blank. */
    Optional<String> getString(String name);

    /** @param defaultValue used when unset or unparseable. */
    int getInt(String name, int defaultValue);

    /** @param defaultValue used when unset. */
    boolean getBoolean(String name, boolean defaultValue);

    /** Resolves a path, confined to the deployment directories. A path outside them resolves to empty. */
    Optional<String> getPath(String name);
}
