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
import org.wso2.carbon.identity.breach.source.Credential;

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
 * The file is taken as it is: entries already hashed are read as digests, entries in plaintext are hashed on the
 * way in. Either way the result is one set of digests, and a lookup is one set membership test. There is no
 * ordering requirement, no storage regime to pick, and nothing an entry can say that changes what the loader
 * does - a line is a password or a digest, never a directive, a path, or markup.
 */
public class BlocklistLoader {

    private static final Log LOG = LogFactory.getLog(BlocklistLoader.class);

    private BlocklistLoader() {

    }

    /**
     * Read the file and index it.
     *
     * @param path       the file, already confined to a permitted location by the configuration layer.
     * @param format     how the file is written, as the operator declared it.
     * @param maxEntries the ceiling, beyond which loading stops and reports truncation.
     * @return the snapshot.
     * @throws IOException if the file cannot be read.
     */
    public static BlocklistSnapshot load(Path path, BlocklistFormat format, int maxEntries) throws IOException {

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
        return new BlocklistSnapshot(digests, format, skipped, truncated, System.currentTimeMillis());
    }

    /**
     * Blank lines and comments are not entries and are not counted as skipped. Only the line ending is
     * stripped: passwords are whitespace-significant, so nothing else is trimmed.
     */
    private static String strip(String line) {

        String content = line;
        if (content.endsWith("\r")) {
            content = content.substring(0, content.length() - 1);
        }
        if (content.isEmpty() || content.startsWith("#")) {
            return null;
        }
        return content;
    }

    /**
     * An already-hashed entry is read as it stands - its algorithm was fixed when the list was dumped and is
     * not ours to change. A plaintext entry is hashed here, so the operator's file is the only place those
     * passwords exist in readable form and a heap dump never carries a list of them.
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
     * Hash a file entry through the same code that hashes a candidate password, so the two cannot drift. That
     * both sides normalize identically - Unicode NFC, UTF-8, no case folding, no trimming - is the invariant
     * the whole lookup rests on; anything else would refuse credentials the operator never listed.
     */
    static String digestOf(String value, String algorithm) {

        return new Credential(value.toCharArray()).digestHex(algorithm);
    }
}
