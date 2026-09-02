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
 * One consistent view of the operator's file: the digests it yielded, paired with the algorithm they were taken
 * with.
 * <p>
 * The two travel together because a lookup needs both, and a reload builds a whole new snapshot before swapping
 * the reference - so an evaluation in flight can never hash a candidate with one algorithm and compare it
 * against digests taken with another.
 */
final class BlocklistSnapshot {

    private final Set<String> digests;
    private final BlocklistFormat format;

    BlocklistSnapshot(Set<String> digests, BlocklistFormat format) {

        this.digests = digests;
        this.format = format;
    }

    boolean contains(String uppercaseHexDigest) {

        return digests.contains(uppercaseHexDigest);
    }

    BlocklistFormat getFormat() {

        return format;
    }
}
