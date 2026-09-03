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
import org.wso2.carbon.identity.breach.detection.SourceConfiguration;
import org.wso2.carbon.identity.breach.detection.util.BreachDetectionUtils;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The deployment settings for one source, resolved from the configuration layer.
 * <p>
 * The source reads nothing itself. It declares the names it uses and the core hands the values over, which is
 * why a connector needs no filesystem access and no vault handle. Secret aliases are already resolved by the
 * configuration layer, so a value arrives here as plain text.
 */
public class ResolvedSourceConfiguration implements SourceConfiguration {

    private static final Log LOG = LogFactory.getLog(ResolvedSourceConfiguration.class);

    private final String sourceId;
    private final Map<String, String> values;
    private final Set<String> declared;

    public ResolvedSourceConfiguration(String sourceId, List<String> declaredNames,
                                       Map<String, String> configured) {

        this.sourceId = sourceId;
        this.declared = new HashSet<>(declaredNames);
        this.values = new HashMap<>();
        if (configured != null) {
            values.putAll(configured);
            reportUnrecognisedKeys();
        }
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

        return BreachDetectionUtils.parseInt(getString(name).orElse(null), defaultValue);
    }


    @Override
    public boolean getBoolean(String name, boolean defaultValue) {

        return BreachDetectionUtils.parseBoolean(getString(name).orElse(null), defaultValue);
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
        } catch (Exception e) {
            LOG.error("Source '" + sourceId + "' was configured with an unusable path for '" + name + "'.");
            return Optional.empty();
        }
        if (!isWithinPermittedRoots(candidate)) {
            // Blocklist data is evaluation data, never a path reference the file itself can redirect.
            LOG.error("Source '" + sourceId + "' was configured with a path for '" + name
                    + "' outside the permitted locations. Ignoring it.");
            return Optional.empty();
        }
        return Optional.of(candidate.toString());
    }

    private boolean isWithinPermittedRoots(Path candidate) {

        Set<Path> roots = new HashSet<>();
        addRoot(roots, safeCarbonHome());
        addRoot(roots, System.getProperty("carbon.config.dir.path"));
        if (roots.isEmpty()) {
            // With no resolvable deployment root there is nothing to confine against; fail closed.
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
        } catch (Exception ignored) {
            // An unusable root simply does not widen the permitted set.
        }
    }

    private static String safeCarbonHome() {

        try {
            return CarbonUtils.getCarbonHome();
        } catch (Throwable t) {
            return System.getProperty("carbon.home");
        }
    }

    private static String expand(String value) {

        String carbonHome = safeCarbonHome();
        String expanded = value;
        if (carbonHome != null) {
            expanded = expanded.replace("${carbon.home}", carbonHome);
        }
        return expanded.replace('/', File.separatorChar);
    }

    private void reportUnrecognisedKeys() {

        for (String key : values.keySet()) {
            if (!declared.contains(key)) {
                // Reported rather than ignored: a typo must not silently leave a connector on its default.
                LOG.warn("Breach detection source '" + sourceId + "' has no setting named '" + key
                        + "'. Check the [breach_detection.sources." + sourceId + "] configuration.");
            }
        }
    }
}
