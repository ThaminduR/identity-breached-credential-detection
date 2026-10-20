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
 * A candidate password being evaluated. Held as a {@code char[]} so that it can be cleared. Never pass
 * it to a log statement, an exception message or a cache key, and never retain it past a call.
 */
public final class Credential {

    private static final String MASK = "Credential{****}";

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private final char[] chars;
    private volatile boolean cleared;

    public Credential(char[] chars) {

        if (chars == null) {
            throw new IllegalArgumentException("Credential characters cannot be null.");
        }
        this.chars = chars;
    }

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

    public String digestHex(String algorithm) {

        byte[] bytes = canonicalBytes();
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] out = digest.digest(bytes);
            char[] hex = new char[out.length * 2];
            for (int i = 0; i < out.length; i++) {
                int v = out[i] & 0xFF;
                hex[i * 2] = HEX[v >>> 4];
                hex[i * 2 + 1] = HEX[v & 0x0F];
            }
            return new String(hex);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported digest algorithm: " + algorithm, e);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    public void clear() {

        Arrays.fill(chars, '\0');
        cleared = true;
    }

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
