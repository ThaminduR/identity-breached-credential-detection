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

import java.util.Locale;

/**
 * How the operator's file is written. Plaintext is hashed at load, so the in-memory form is always digests.
 * <p>
 * There is no {@code auto} member and no fallback value. The file determines the algorithm, and guessing
 * wrong does not raise an error, it silently stops matching. An absent or unrecognised value leaves the
 * source unconfigured.
 */
public enum BlocklistFormat {

    SHA1("sha1", "SHA-1", 40),
    SHA256("sha256", "SHA-256", 64),
    /** Hashed at load with SHA-256, so a plaintext file and a SHA-256 file index identically. */
    PLAINTEXT("plaintext", "SHA-256", -1);

    private final String configValue;
    private final String digestAlgorithm;
    private final int hexLength;

    BlocklistFormat(String configValue, String digestAlgorithm, int hexLength) {

        this.configValue = configValue;
        this.digestAlgorithm = digestAlgorithm;
        this.hexLength = hexLength;
    }

    /**
     * @return the algorithm a candidate password is hashed with to look it up.
     */
    public String getDigestAlgorithm() {

        return digestAlgorithm;
    }

    /**
     * @return the expected hex digest length, or -1 when entries are not hashed in the file.
     */
    public int getHexLength() {

        return hexLength;
    }

    public boolean isHashed() {

        return this == SHA1 || this == SHA256;
    }

    /**
     * @param value the configured value.
     * @return the format, or {@code null} when nothing recognisable was configured.
     */
    public static BlocklistFormat from(String value) {

        if (value == null) {
            return null;
        }
        switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "sha1":
            case "sha-1":
                return SHA1;
            case "sha256":
            case "sha-256":
                return SHA256;
            case "plaintext":
            case "plain":
                return PLAINTEXT;
            default:
                return null;
        }
    }

    /**
     * @return the value as it appears in configuration.
     */
    public String toConfigValue() {

        return configValue;
    }
}
