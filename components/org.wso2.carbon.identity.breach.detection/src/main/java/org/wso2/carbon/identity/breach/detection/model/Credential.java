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

package org.wso2.carbon.identity.breach.detection.model;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.Arrays;

/**
 * The candidate password, held as a {@code char[]} so that it can be cleared and does not enter the string
 * pool.
 * <p>
 * Do not pass this value to a log statement, an exception message or a cache key. The engine clears it after
 * the last source returns. A source must not retain it.
 */
public final class Credential {

    private static final String MASK = "Credential{****}";

    private final char[] chars;
    private volatile boolean cleared;

    /**
     * @param chars the candidate password. Taken by reference: the caller must not mutate or reuse it.
     */
    public Credential(char[] chars) {

        if (chars == null) {
            throw new IllegalArgumentException("Credential characters cannot be null.");
        }
        this.chars = chars;
    }


    /**
     * @return the number of characters. Safe to log.
     */
    public int length() {

        return chars.length;
    }

    /**
     * Returns the canonical bytes of the password: Unicode NFC, UTF-8, with no case folding and no
     * trimming, because a password is case- and whitespace-significant. Private, because
     * {@link #digestHex(String)} is the only caller.
     */
    private byte[] canonicalBytes() {

        assertUsable();
        CharBuffer canonical = canonicalChars();
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(canonical);
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        if (encoded.hasArray()) {
            Arrays.fill(encoded.array(), (byte) 0);
        }
        if (canonical.hasArray() && canonical.array() != chars) {
            Arrays.fill(canonical.array(), '\0');
        }
        return bytes;
    }

    /**
     * Returns the digest of the canonical bytes as uppercase hex. A source matches on this value.
     *
     * @param algorithm a {@link MessageDigest} algorithm name, for example {@code SHA-1}.
     * @return uppercase hex digest.
     * @throws IllegalArgumentException if the algorithm is not available.
     */
    public String digestHex(String algorithm) {

        byte[] bytes = canonicalBytes();
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] out = digest.digest(bytes);
            char[] hex = new char[out.length * 2];
            for (int i = 0; i < out.length; i++) {
                int v = out[i] & 0xFF;
                hex[i * 2] = Character.forDigit(v >>> 4, 16);
                hex[i * 2 + 1] = Character.forDigit(v & 0x0F, 16);
            }
            return new String(hex).toUpperCase(java.util.Locale.ROOT);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported digest algorithm: " + algorithm, e);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Zeroes the backing array. The engine calls this after every source has returned.
     */
    public void clear() {

        Arrays.fill(chars, '\0');
        cleared = true;
    }

    /**
     * @return {@code true} once {@link #clear()} has run.
     */
    public boolean isCleared() {

        return cleared;
    }

    private CharBuffer canonicalChars() {

        CharBuffer raw = CharBuffer.wrap(chars);
        if (Normalizer.isNormalized(raw, Normalizer.Form.NFC)) {
            return raw;
        }
        return CharBuffer.wrap(Normalizer.normalize(raw, Normalizer.Form.NFC).toCharArray());
    }

    private void assertUsable() {

        if (cleared) {
            throw new IllegalStateException("The credential has already been cleared.");
        }
    }

    @Override
    public String toString() {

        return MASK;
    }
}
