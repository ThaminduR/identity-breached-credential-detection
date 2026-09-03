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
import org.wso2.carbon.identity.breach.source.BreachContext;
import org.wso2.carbon.identity.breach.source.BreachSource;
import org.wso2.carbon.identity.breach.source.BreachVerdict;
import org.wso2.carbon.identity.breach.source.FailureAction;
import org.wso2.carbon.identity.breach.source.PropertyDescriptor;
import org.wso2.carbon.identity.breach.source.SourceConfiguration;
import org.wso2.carbon.identity.breach.source.UnavailableCause;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The operator's own list of forbidden passwords, answered without touching the network.
 * <p>
 * The only source that ships in the core, and the only one that is not a connector. It earns that on two
 * grounds: it crosses no boundary, so there is no third-party API to track, and it is what makes the capability
 * work at all in a network-isolated deployment. It is also the floor that keeps enforcing when every remote
 * source is down - which is what makes {@code allow} a defensible default failure policy rather than a shrug.
 * <p>
 * It registers through the same registry as any connector and gets no privileged path from the engine.
 */
public class LocalBlocklistSource implements BreachSource {

    private static final Log LOG = LogFactory.getLog(LocalBlocklistSource.class);

    public static final String PROPERTY_ENABLE = "enable";
    public static final String PROPERTY_PATH = "path";
    public static final String PROPERTY_FORMAT = "format";
    public static final String PROPERTY_MAX_HEAP_ENTRIES = "max_heap_entries";

    /**
     * A count, not a byte budget: measured at 122.5 bytes an entry for a 40-character digest and 146.5 for a
     * 64-character one, so this ceiling costs 584 MB or 699 MB depending on the format.
     */
    private static final int DEFAULT_MAX_HEAP_ENTRIES = 5_000_000;


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
    public List<PropertyDescriptor> getProperties() {

        return Arrays.asList(
                PropertyDescriptor.builder(PROPERTY_ENABLE).defaultValue("true").build(),
                PropertyDescriptor.builder(PROPERTY_PATH).required(true).build(),
                PropertyDescriptor.builder(PROPERTY_FORMAT).required(true).build(),
                PropertyDescriptor.builder(PROPERTY_MAX_HEAP_ENTRIES)
                        .defaultValue(String.valueOf(DEFAULT_MAX_HEAP_ENTRIES)).build());
    }

    @Override
    public int getPriority() {

        // In-process and certain. Consulted before any network round trip, so the passwords an operator most
        // wants blocked never leave the deployment and never consume third-party quota.
        return 100;
    }

    @Override
    public void configure(SourceConfiguration configuration) {

        boolean enable = configuration.getBoolean(PROPERTY_ENABLE, true);
        BlocklistFormat format = BlocklistFormat.from(configuration.getString(PROPERTY_FORMAT).orElse(null));
        int maxEntries = configuration.getInt(PROPERTY_MAX_HEAP_ENTRIES, DEFAULT_MAX_HEAP_ENTRIES);
        String configuredPath = configuration.getPath(PROPERTY_PATH).orElse(null);

        // Configuration is handed over on bind and again on every reconfiguration, so an unchanged
        // configuration must not rebuild an index that is already correct.
        boolean unchanged = snapshot.get() != null
                && format == configuredFormat
                && maxEntries == maxHeapEntries
                && path != null && path.toString().equals(configuredPath);

        this.enabled = enable;
        this.configuredFormat = format;
        this.maxHeapEntries = maxEntries;
        this.path = configuredPath == null ? null : Paths.get(configuredPath);
        if (!enable) {
            // Released rather than merely ignored: a parked corpus should cost neither heap nor a mapping.
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
     * Supplying a readable file is still what switches the list on; {@link #PROPERTY_ENABLE} exists to park a
     * configured list without unpicking its settings. It is a deployment property rather than a per-tenant one
     * because the file itself is deployment-wide - a tenant-level toggle over one shared file would let two
     * organizations disagree about a thing neither of them owns.
     */
    @Override
    public boolean isEnabled(String tenantDomain) {

        return enabled && path != null && snapshot.get() != null;
    }



    /**
     * Allow, not deny. A list that failed to load reports itself disabled above, so the engine never consults
     * it and this value is not reached. See the open question on that behaviour.
     */
    @Override
    public FailureAction getFailureAction(String tenantDomain) {

        return FailureAction.ALLOW;
    }

    @Override
    public BreachVerdict evaluate(BreachContext context) {

        BlocklistSnapshot current = snapshot.get();
        if (current == null) {
            // Not being able to check is not the same as finding nothing, and is never reported as if it were.
            return BreachVerdict.unavailable(getId(), UnavailableCause.MISCONFIGURED,
                    "No blocklist is loaded.");
        }
        String digest = context.getCredential().digestHex(current.getFormat().getDigestAlgorithm());
        return current.contains(digest) ? BreachVerdict.found(getId()) : BreachVerdict.notFound(getId());
    }

    /**
     * Rebuild the index from the configured file.
     * <p>
     * The new index is built in full before the reference is swapped, so an evaluation in flight always sees one
     * consistent view. A file that cannot be parsed leaves the previously loaded list in effect and reports the
     * failure rather than quietly emptying the list.
     *
     */
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

    /**
     * Release the list.
     */
    public void shutdown() {

        snapshot.set(null);
    }


}
