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
 * The resolved deployment settings for one source.
 * <p>
 * The core reads the configuration and passes the values to the source through
 * {@link BreachSource#configure}. A source does not read a configuration file and does not resolve a secret
 * alias. Each accessor takes the fallback value to use when the setting is absent.
 */
public interface SourceConfiguration {

    /**
     * @param name property name.
     * @return the configured value, or empty when it is unset or blank.
     */
    Optional<String> getString(String name);

    /**
     * @param name         property name.
     * @param defaultValue value to use when unset or unparseable.
     * @return the resolved integer.
     */
    int getInt(String name, int defaultValue);


    /**
     * @param name         property name.
     * @param defaultValue value to use when unset.
     * @return the resolved flag.
     */
    boolean getBoolean(String name, boolean defaultValue);

    /**
     * Resolve a path, confined to the deployment and configuration directories. A path outside them resolves
     * to empty and is logged.
     *
     * @param name property name.
     * @return the resolved absolute path, or empty.
     */
    Optional<String> getPath(String name);
}
