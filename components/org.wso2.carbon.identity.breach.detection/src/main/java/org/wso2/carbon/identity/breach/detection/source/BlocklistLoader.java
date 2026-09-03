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
import org.wso2.carbon.identity.breach.detection.model.Credential;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Builds a {@link BlocklistSnapshot} from the operator's file.
 * <p>
 * Hashed entries are read as digests and plaintext entries are hashed on the way in, so both produce one set
 * of digests. Every line is treated as data. A line is a password or a digest, and is never interpreted as a
 * directive or a path.
 */
class BlocklistLoader {

    private static final Log LOG = LogFactory.getLog(BlocklistLoader.class);

    private BlocklistLoader() {

    }

    /**
     * Read the file and index it.
     *
     * @param path       the file, already confined to a permitted location by the configuration layer.
     * @param format     how the file is written, as the operator configured it.
     * @param maxEntries the ceiling, beyond which loading stops and reports truncation.
     * @return the snapshot.
     * @throws IOException if the file cannot be read.
     */
    static BlocklistSnapshot load(Path path, BlocklistFormat format, int maxEntries) throws IOException {

        Set<String> digests = new HashSet<>();
        long skipped = 0;
        boolean truncated = false;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(Files.newInputStream(path), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (digests.size() >= maxEntries) {
                    truncated = true;
                    break;
                }
                String content = strip(line);
                if (content == null) {
                    continue;
                }
                String digest = toDigest(content, format);
                if (digest == null) {
                    skipped++;
                    continue;
                }
                digests.add(digest);
            }
        }

        if (truncated) {
            LOG.error("The breach blocklist at " + path + " exceeds the maximum of " + maxEntries
                    + " entries and was loaded only up to that point. The remainder of the file is not being "
                    + "enforced.");
        }
        if (skipped > 0) {
            LOG.warn("Loaded the breach blocklist from " + path + " with " + skipped
                    + " malformed or unrecognised entries ignored.");
        }
        LOG.info("Loaded the breach blocklist: entries=" + digests.size() + ", skipped=" + skipped
                + ", format=" + format.toConfigValue() + ".");
        return new BlocklistSnapshot(digests, format);
    }

    /**
     * Blank lines and comments are not entries and are not counted as skipped. Nothing is trimmed, because a
     * password is whitespace-significant, and {@code readLine} has already removed the line ending.
     */
    private static String strip(String line) {

        return line.isEmpty() || line.startsWith("#") ? null : line;
    }

    /**
     * A hashed entry is read as it stands, because its algorithm was fixed when the list was produced. A
     * plaintext entry is hashed here, so that only the digest is held for the life of the list.
     */
    private static String toDigest(String content, BlocklistFormat format) {

        if (format.isHashed()) {
            // The HIBP download and most dumps carry an occurrence count after the digest.
            int separator = content.indexOf(':');
            String candidate = (separator < 0 ? content : content.substring(0, separator)).trim();
            if (candidate.length() != format.getHexLength() || !isHex(candidate)) {
                return null;
            }
            return candidate.toUpperCase(Locale.ROOT);
        }
        return digestOf(content, format.getDigestAlgorithm());
    }

    private static boolean isHex(String value) {

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    /**
     * Hashes a file entry with the same code that hashes a candidate password, so that loading and lookup
     * cannot normalize differently.
     */
    static String digestOf(String value, String algorithm) {

        return new Credential(value.toCharArray()).digestHex(algorithm);
    }
}
