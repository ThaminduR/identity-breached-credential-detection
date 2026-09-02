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

package org.wso2.carbon.identity.breach.detection.engine;

/**
 * What the capability was actually doing when a password was evaluated.
 * <p>
 * The distinction between {@link #ENFORCING} and everything below it is the point of the whole design, and it
 * is why {@link #NOT_ENFORCING} is logged at a severity that supports alerting: nothing may look healthy while
 * no verdict can be produced.
 */
public enum EnforcementStatus {

    /** No source is enabled here, so nothing is being checked. */
    OFF,

    /** Every enabled source is answering. */
    ENFORCING,

    /** At least one enabled source cannot answer, and at least one still can. */
    DEGRADED,

    /** No enabled source can currently produce a verdict. Raised at a severity that supports alerting. */
    NOT_ENFORCING
}
