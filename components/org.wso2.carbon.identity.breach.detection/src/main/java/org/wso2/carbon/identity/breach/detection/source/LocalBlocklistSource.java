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
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The operator's own list of forbidden passwords, answered from memory. The only source that ships in the
 * bundle, and it registers through the same registry as a connector with no privileged path.
 */
public class LocalBlocklistSource implements BreachSource {

    private static final Log LOG = LogFactory.getLog(LocalBlocklistSource.class);

    public static final String PROPERTY_ENABLE = "enable";
    public static final String PROPERTY_PATH = "path";
    public static final String PROPERTY_FORMAT = "format";
    public static final String PROPERTY_MAX_HEAP_ENTRIES = "max_heap_entries";

    /**
     * Caps the entry count, not the bytes. At a measured 122.5 bytes per 40-character digest this costs
     * about 123 MB, against the 1 GB heap the pack ships with.
     */
    private static final int DEFAULT_MAX_HEAP_ENTRIES = 1_000_000;

    private final AtomicReference<BlocklistSnapshot> snapshot = new AtomicReference<>();

    private volatile boolean enabled = true;
    private volatile Path path;
    private volatile BlocklistFormat configuredFormat;
    private volatile int maxHeapEntries = DEFAULT_MAX_HEAP_ENTRIES;

    @Override
    public String getId() {

        return BreachDetectionConstants.LOCAL_LIST_SOURCE_ID;
    }

    @Override
    public int getPriority() {

        // Called before any network request, so the passwords an operator most wants blocked do not leave
        // the deployment and do not consume third-party quota.
        return 100;
    }

    @Override
    public void configure(SourceConfiguration configuration) {

        boolean enable = configuration.getBoolean(PROPERTY_ENABLE, true);
        BlocklistFormat format = BlocklistFormat.from(configuration.getString(PROPERTY_FORMAT).orElse(null));
        int maxEntries = configuration.getInt(PROPERTY_MAX_HEAP_ENTRIES, DEFAULT_MAX_HEAP_ENTRIES);
        String configuredPath = configuration.getPath(PROPERTY_PATH).orElse(null);

        // Configuration is handed over on bind and again on every reconfiguration, so an unchanged
        // configuration must not rebuild a list that is already correct.
        boolean unchanged = snapshot.get() != null
                && format == configuredFormat
                && maxEntries == maxHeapEntries
                && path != null && path.toString().equals(configuredPath);

        this.enabled = enable;
        this.configuredFormat = format;
        this.maxHeapEntries = maxEntries;
        this.path = configuredPath == null ? null : Paths.get(configuredPath);
        if (!enable) {
            // Release the digests so that a list that is switched off uses no heap.
            snapshot.set(null);
            LOG.info("The local breach blocklist is switched off in deployment configuration.");
            return;
        }
        if (path == null || format == null) {
            snapshot.set(null);
            LOG.warn("The local breach blocklist needs both a path and a format. It will not be consulted.");
            return;
        }
        if (!unchanged) {
            reload();
        }
    }

    /**
     * A readable file is what switches the list on. {@link #PROPERTY_ENABLE} parks a configured list without
     * removing its settings, and is deployment-wide because the file is.
     */
    @Override
    public boolean isEnabled(String tenantDomain) {

        return enabled && path != null && snapshot.get() != null;
    }

    /** A list that failed to load accepts. {@link #isEnabled} is false then, so the engine skips it. */
    @Override
    public Decision check(Credential credential, String tenantDomain) {

        BlocklistSnapshot current = snapshot.get();
        if (current == null) {
            return Decision.ACCEPT;
        }
        String digest = credential.digestHex(current.getFormat().getDigestAlgorithm());
        return current.contains(digest) ? Decision.REFUSE_BREACHED : Decision.ACCEPT;
    }

    /** Built in full before the reference is replaced. An unreadable file leaves the previous list. */
    private void reload() {

        Path current = path;
        if (!Files.isReadable(current)) {
            LOG.error("The breach blocklist file is not readable. Path: " + current);
            return;
        }
        try {
            snapshot.set(BlocklistLoader.load(current, configuredFormat, maxHeapEntries));
        } catch (Exception e) {
            LOG.error("The breach blocklist file could not be parsed. The previously loaded list stays in "
                    + "effect. Path: " + current, e);
        }
    }

    /** Releases the list. */
    public void shutdown() {

        snapshot.set(null);
    }

}
