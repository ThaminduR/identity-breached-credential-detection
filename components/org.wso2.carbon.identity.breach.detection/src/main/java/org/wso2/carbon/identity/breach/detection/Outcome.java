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

package org.wso2.carbon.identity.breach.detection;

/**
 * What a source concluded about a candidate password.
 * <p>
 * {@link #UNAVAILABLE} and {@link #NOT_FOUND} are different results. A source that could not reach its
 * corpus returns {@code UNAVAILABLE}. If a source reports the two as equivalent, enforcement stops while the
 * source continues to report itself as enabled.
 */
public enum Outcome {

    /** The source reports the password as present in its corpus. */
    FOUND,

    /** The source positively reports the password as absent from its corpus. */
    NOT_FOUND,

    /** The source could not answer. The failure policy configured for the source decides the result. */
    UNAVAILABLE
}
