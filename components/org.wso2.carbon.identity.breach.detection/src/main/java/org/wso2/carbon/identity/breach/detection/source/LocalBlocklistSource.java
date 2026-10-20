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

package org.wso2.carbon.identity.breach.detection.source;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.breach.detection.constants.BreachDetectionConstants;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Breach source backed by an operator-supplied blocklist file, answered from memory. It registers as an
 * OSGi service like any connector and has no privileged path through the engine.
 */
public class LocalBlocklistSource implements BreachSource {

    private static final Log LOG = LogFactory.getLog(LocalBlocklistSource.class);

    public static final String PROPERTY_ENABLE = "enable";
    public static final String PROPERTY_PATH = "path";
    public static final String PROPERTY_FORMAT = "format";
    public static final String PROPERTY_MAX_HEAP_ENTRIES = "max_heap_entries";

    // Caps the entry count, not the bytes. At a measured 122.5 bytes per 40-character digest this
    // costs about 123 MB, against the 1 GB heap the pack ships with.
    private static final int DEFAULT_MAX_HEAP_ENTRIES = 1_000_000;

    private final AtomicReference<Snapshot> snapshot = new AtomicReference<>();

    @Override
    public String getId() {

        return BreachDetectionConstants.LOCAL_LIST_SOURCE_ID;
    }

    @Override
    public int getPriority() {

        return 100;
    }

    @Override
    public void configure(SourceConfiguration configuration) {

        if (!configuration.getBoolean(PROPERTY_ENABLE, true)) {
            snapshot.set(null);
            LOG.info("The local breach blocklist is switched off in deployment configuration.");
            return;
        }
        BlocklistLoader.Format format =
                BlocklistLoader.Format.from(configuration.getString(PROPERTY_FORMAT).orElse(null));
        String configuredPath = configuration.getPath(PROPERTY_PATH).orElse(null);
        if (configuredPath == null || format == null) {
            snapshot.set(null);
            LOG.warn("The local breach blocklist needs both a path and a format. It will not be consulted.");
            return;
        }
        load(Paths.get(configuredPath), format,
                configuration.getInt(PROPERTY_MAX_HEAP_ENTRIES, DEFAULT_MAX_HEAP_ENTRIES));
    }

    @Override
    public boolean isEnabled(String tenantDomain) {

        return snapshot.get() != null;
    }

    @Override
    public Decision check(Credential credential, String tenantDomain) {

        Snapshot current = snapshot.get();
        if (current == null) {
            return Decision.ACCEPT;
        }
        String digest = credential.digestHex(current.algorithm);
        return current.digests.contains(digest) ? Decision.REFUSE_BREACHED : Decision.ACCEPT;
    }

    private void load(Path path, BlocklistLoader.Format format, int maxEntries) {

        // Built in full before the reference is replaced, so a half-written file cannot produce partial
        // matching. An unreadable or unparseable file leaves the previous list in effect.
        if (!Files.isReadable(path)) {
            LOG.error("The breach blocklist file is not readable. Path: " + path);
            return;
        }
        try {
            snapshot.set(new Snapshot(BlocklistLoader.load(path, format, maxEntries), format.getAlgorithm()));
        } catch (IOException e) {
            LOG.error("The breach blocklist file could not be read. The previously loaded list stays in "
                    + "effect. Path: " + path, e);
        }
    }

    public void shutdown() {

        snapshot.set(null);
    }

    /**
     * Digests and the algorithm they were taken with, swapped as one reference so a reconfiguration
     * cannot leave an evaluation hashing with one algorithm and matching against another.
     */
    private static final class Snapshot {

        private final Set<String> digests;
        private final String algorithm;

        Snapshot(Set<String> digests, String algorithm) {

            this.digests = digests;
            this.algorithm = algorithm;
        }
    }
}
