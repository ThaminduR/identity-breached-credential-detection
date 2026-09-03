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

import org.testng.annotations.Test;
import org.wso2.carbon.identity.breach.detection.model.Credential;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Loading the operator's file: the formats accepted, what counts as malformed, and the normalization that has
 * to agree exactly with how a candidate password is hashed.
 */
public class BlocklistLoaderTest {

    @Test
    public void loadsAHashedSha1File() throws IOException {

        Path file = write("sha1", Arrays.asList(
                "# a comment",
                "",
                sha("SHA-1", "Password@1"),
                sha("SHA-1", "Qwerty@123") + ":922923"));
        BlocklistSnapshot snapshot = BlocklistLoader.load(file, BlocklistFormat.SHA1, 1000);

        assertTrue(snapshot.contains(digestOf("Password@1", "SHA-1")));
        assertFalse(snapshot.contains(digestOf("# a comment", "SHA-1")),
                "A comment is not an entry.");
        assertTrue(snapshot.contains(digestOf("Qwerty@123", "SHA-1")),
                "The optional occurrence-count suffix must be ignored.");
        assertFalse(snapshot.contains(digestOf("Zx9q!Kt7#Lm2vRb4", "SHA-1")));
    }

    @Test
    public void loadsAHashedSha256File() throws IOException {

        Path file = write("sha256", Arrays.asList(sha("SHA-256", "Password@1")));
        BlocklistSnapshot snapshot = BlocklistLoader.load(file, BlocklistFormat.SHA256, 1000);
        assertTrue(snapshot.contains(digestOf("Password@1", "SHA-256")));
    }

    @Test
    public void hashesAPlaintextFileAtLoadSoItNeverPersistsInThatFormInside() throws IOException {

        Path file = write("plain", Arrays.asList("Password@1", "correct horse battery staple"));
        BlocklistSnapshot snapshot = BlocklistLoader.load(file, BlocklistFormat.PLAINTEXT, 1000);

        // The candidate is hashed by the credential; the entry was hashed at load. They must agree exactly.
        assertTrue(snapshot.contains(
                new Credential("correct horse battery staple".toCharArray()).digestHex("SHA-256")));
        assertTrue(snapshot.contains(new Credential("Password@1".toCharArray()).digestHex("SHA-256")));
    }

    /**
     * The file dictates the algorithm, so an undeclared or misspelled one must not resolve to a guess: a
     * wrong algorithm does not fail, it silently stops matching.
     */
    @Test
    public void anUndeclaredOrUnrecognisedFormatIsNotGuessed() {

        assertNull(BlocklistFormat.from(null));
        assertNull(BlocklistFormat.from(""));
        assertNull(BlocklistFormat.from("auto"));
        assertNull(BlocklistFormat.from("sha-512"));
        assertNull(BlocklistFormat.from("sha-1"), "Only the documented spellings are accepted.");
        assertNull(BlocklistFormat.from("plain"), "Only the documented spellings are accepted.");
        assertEquals(BlocklistFormat.from("SHA1"), BlocklistFormat.SHA1);
        assertEquals(BlocklistFormat.from(" sha256 "), BlocklistFormat.SHA256);
        assertEquals(BlocklistFormat.from("plaintext"), BlocklistFormat.PLAINTEXT);
    }

    @Test
    public void aMalformedEntryIsDroppedWithoutTakingTheRestOfTheFileWithIt() throws IOException {

        Path file = write("mixed", Arrays.asList(
                sha("SHA-1", "Password@1"),
                "NOTAHASH",
                "ZZZZ61E4C9B93F3F0682250B6CF8331B7EE68FD8",
                "5BAA61E4C9B93F3F0682250B6CF8331B7EE68",
                sha("SHA-1", "Qwerty@123")));
        BlocklistSnapshot snapshot = BlocklistLoader.load(file, BlocklistFormat.SHA1, 1000);

        // The two well-formed entries either side of the malformed ones still load.
        assertTrue(snapshot.contains(digestOf("Password@1", "SHA-1")));
        assertTrue(snapshot.contains(digestOf("Qwerty@123", "SHA-1")));
        assertFalse(snapshot.contains("NOTAHASH"));
        assertFalse(snapshot.contains("ZZZZ61E4C9B93F3F0682250B6CF8331B7EE68FD8"));
    }

    @Test
    public void plaintextEntriesAreCaseAndWhitespaceSignificant() throws IOException {

        Path file = write("ws", Arrays.asList("  Padded  ", "MixedCase"));
        BlocklistSnapshot snapshot = BlocklistLoader.load(file, BlocklistFormat.PLAINTEXT, 100);

        assertTrue(snapshot.contains(new Credential("  Padded  ".toCharArray()).digestHex("SHA-256")));
        assertFalse(snapshot.contains(new Credential("Padded".toCharArray()).digestHex("SHA-256")),
                "Trimming would refuse a credential the operator never listed.");
        assertFalse(snapshot.contains(new Credential("mixedcase".toCharArray()).digestHex("SHA-256")),
                "Case folding would do the same.");
    }

    @Test
    public void aFileBeyondTheCeilingStopsThereRatherThanSpillingPastIt() throws IOException {

        List<String> lines = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            lines.add(sha("SHA-1", "password" + i));
        }
        BlocklistSnapshot snapshot = BlocklistLoader.load(write("big", lines), BlocklistFormat.SHA1, 10);

        assertTrue(snapshot.contains(digestOf("password0", "SHA-1")), "the first entry is loaded");
        assertFalse(snapshot.contains(digestOf("password49", "SHA-1")),
                "entries past the ceiling are not enforced, and the loader logs that at ERROR");
    }

    @Test
    public void aLowercaseSortedCorpusStillMatches() throws IOException {

        List<String> digests = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            digests.add(sha("SHA-1", "lower" + i).toLowerCase(Locale.ROOT));
        }
        digests.sort(String::compareTo);
        BlocklistSnapshot snapshot =
                BlocklistLoader.load(write("lower", digests), BlocklistFormat.SHA1, 1000);
        assertTrue(snapshot.contains(digestOf("lower42", "SHA-1")));
    }

    private static String digestOf(String password, String algorithm) {

        return new Credential(password.toCharArray()).digestHex(algorithm);
    }

    private static Path write(String name, List<String> lines) throws IOException {

        Path file = Files.createTempFile("blocklist-" + name + "-", ".txt");
        file.toFile().deleteOnExit();
        Files.write(file, String.join("\n", lines).concat("\n").getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static String sha(String algorithm, String value) {

        try {
            byte[] out = MessageDigest.getInstance(algorithm).digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : out) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString().toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
