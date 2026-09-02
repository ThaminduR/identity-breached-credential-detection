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

import java.util.Set;

/**
 * One consistent view of the operator's file: the digests it yielded, and what happened while reading it.
 * <p>
 * A reload builds a whole new snapshot before swapping the reference, so an evaluation in flight always sees one
 * consistent view and a half-written file can never produce partial matching.
 */
public final class BlocklistSnapshot {

    private final Set<String> digests;
    private final BlocklistFormat format;
    private final long skipped;
    private final boolean truncated;
    private final long loadedAtEpochMillis;

    BlocklistSnapshot(Set<String> digests, BlocklistFormat format, long skipped, boolean truncated,
                      long loadedAtEpochMillis) {

        this.digests = digests;
        this.format = format;
        this.skipped = skipped;
        this.truncated = truncated;
        this.loadedAtEpochMillis = loadedAtEpochMillis;
    }

    /**
     * @param uppercaseHexDigest the candidate's digest, taken with {@link BlocklistFormat#getDigestAlgorithm()}.
     * @return whether the digest is listed.
     */
    public boolean contains(String uppercaseHexDigest) {

        return digests.contains(uppercaseHexDigest);
    }

    public BlocklistFormat getFormat() {

        return format;
    }

    public long getEntries() {

        return digests.size();
    }

    /**
     * @return how many entries were malformed or unrecognised. Reported on every load: an operator has to be
     * able to tell the difference between a file that loaded and a file that mostly did not.
     */
    public long getSkipped() {

        return skipped;
    }

    /**
     * @return whether the file exceeded the maximum entry count and was cut short.
     */
    public boolean isTruncated() {

        return truncated;
    }

    public long getLoadedAtEpochMillis() {

        return loadedAtEpochMillis;
    }
}
