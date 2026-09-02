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

package org.wso2.carbon.identity.breach.source;

/**
 * What a source wants done with a password it could not check.
 * <p>
 * Each source answers this for itself, per organization, because the right answer differs by source. An
 * offline list that fails to load is a broken file an operator can fix in minutes, so refusing costs little.
 * A hosted corpus that cannot be reached is somebody else's outage, and refusing would let them stop every
 * password change in the deployment.
 */
public enum FailureAction {

    /** Let the password through, and record the gap in telemetry. */
    ALLOW,

    /** Refuse the password, with a message distinguishable from a breach. */
    DENY
}
