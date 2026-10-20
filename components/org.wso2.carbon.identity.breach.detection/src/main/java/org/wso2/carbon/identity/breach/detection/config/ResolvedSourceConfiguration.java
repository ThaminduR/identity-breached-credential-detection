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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Resolved deployment settings for a single breach source. Secret aliases are already expanded, so
 * every value returned is plain text.
 */
public class ResolvedSourceConfiguration implements SourceConfiguration {

    private static final Log LOG = LogFactory.getLog(ResolvedSourceConfiguration.class);

    private final String sourceId;
    private final Map<String, String> values;

    public ResolvedSourceConfiguration(String sourceId, Map<String, String> configured) {

        this.sourceId = sourceId;
        this.values = configured == null ? new HashMap<>() : new HashMap<>(configured);
    }

    @Override
    public Optional<String> getString(String name) {

        String value = values.get(name);
        if (value == null || value.trim().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(value.trim());
    }

    @Override
    public int getInt(String name, int defaultValue) {

        String value = getString(name).orElse(null);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    @Override
    public boolean getBoolean(String name, boolean defaultValue) {

        return getString(name).map(Boolean::parseBoolean).orElse(defaultValue);
    }

    @Override
    public Optional<String> getPath(String name) {

        Optional<String> configured = getString(name);
        if (!configured.isPresent()) {
            return Optional.empty();
        }
        String raw = expand(configured.get());
        Path candidate;
        try {
            candidate = Paths.get(raw).toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            LOG.error("Source '" + sourceId + "' was configured with an unusable path for '" + name + "'.");
            return Optional.empty();
        }
        if (!isWithinPermittedRoots(candidate)) {
            LOG.error("Source '" + sourceId + "' was configured with a path for '" + name
                    + "' outside the permitted locations. Ignoring it.");
            return Optional.empty();
        }
        return Optional.of(candidate.toString());
    }

    private boolean isWithinPermittedRoots(Path candidate) {

        Set<Path> roots = new HashSet<>();
        addRoot(roots, CarbonUtils.getCarbonHome());
        addRoot(roots, System.getProperty("carbon.config.dir.path"));
        if (roots.isEmpty()) {
            // With no resolvable deployment root there is nothing to confine against, so fail closed.
            return false;
        }
        for (Path root : roots) {
            if (candidate.startsWith(root)) {
                return true;
            }
        }
        return false;
    }

    private static void addRoot(Set<Path> roots, String raw) {

        if (raw == null || raw.trim().isEmpty()) {
            return;
        }
        try {
            roots.add(Paths.get(raw).toAbsolutePath().normalize());
        } catch (InvalidPathException ignored) {
        }
    }

    private static String expand(String value) {

        String carbonHome = CarbonUtils.getCarbonHome();
        String expanded = value;
        if (carbonHome != null) {
            expanded = expanded.replace("${carbon.home}", carbonHome);
        }
        return expanded.replace('/', File.separatorChar);
    }
}
