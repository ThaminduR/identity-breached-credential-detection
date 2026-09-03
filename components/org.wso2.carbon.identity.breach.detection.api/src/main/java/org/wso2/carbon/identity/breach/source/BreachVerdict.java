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
 * What one source concluded.
 * <p>
 * The engine branches on the outcome. The source id and reason exist for {@link #toString()}, which is what
 * the not-enforcing log prints, so an operator can see why each source failed.
 */
public final class BreachVerdict {

    private final Outcome outcome;
    private final String sourceId;
    private final String reason;

    private BreachVerdict(Outcome outcome, String sourceId, String reason) {

        this.outcome = outcome;
        this.sourceId = sourceId;
        this.reason = reason;
    }

    /**
     * @param sourceId reporting source.
     * @return the password is in this source's corpus.
     */
    public static BreachVerdict found(String sourceId) {

        return new BreachVerdict(Outcome.FOUND, sourceId, null);
    }

    /**
     * @param sourceId reporting source.
     * @return the source positively determined the password is absent.
     */
    public static BreachVerdict notFound(String sourceId) {

        return new BreachVerdict(Outcome.NOT_FOUND, sourceId, null);
    }

    /**
     * @param sourceId reporting source.
     * @param reason   what went wrong, for the log. Must carry no part of the credential.
     * @return the source could not produce a verdict.
     */
    public static BreachVerdict unavailable(String sourceId, String reason) {

        return new BreachVerdict(Outcome.UNAVAILABLE, sourceId, reason);
    }

    public Outcome getOutcome() {

        return outcome;
    }

    @Override
    public String toString() {

        return "BreachVerdict{sourceId=" + sourceId + ", outcome=" + outcome
                + (reason == null ? "" : ", reason=" + reason) + '}';
    }
}
