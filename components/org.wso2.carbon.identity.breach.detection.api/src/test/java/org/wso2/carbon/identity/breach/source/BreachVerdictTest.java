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

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unavailable is not not-found. Collapsing the two is the defect the whole design is organised against, so it
 * gets a test rather than a comment.
 */
public class BreachVerdictTest {

    @Test
    public void unavailableIsItsOwnOutcomeAndCarriesACause() {

        BreachVerdict verdict = BreachVerdict.unavailable("hibp", "no answer within 1500 ms");
        assertEquals(verdict.getOutcome(), Outcome.UNAVAILABLE);
        // The reason reaches an operator only through toString, which the not-enforcing log prints.
        assertTrue(verdict.toString().contains("hibp"));
        assertTrue(verdict.toString().contains("no answer within 1500 ms"));
    }

    @Test
    public void anUnavailableVerdictWithNoReasonStillNamesItsSource() {

        assertTrue(BreachVerdict.unavailable("x", null).toString().contains("x"));
    }

    @Test
    public void notFoundIsPositiveAndCarriesNoCause() {

        BreachVerdict verdict = BreachVerdict.notFound("localList");
        assertEquals(verdict.getOutcome(), Outcome.NOT_FOUND);
        assertFalse(verdict.toString().contains("reason"));
    }

    @Test
    public void theStringFormNamesTheSourceAndNothingElse() {

        String text = BreachVerdict.found("hibp").toString();
        assertTrue(text.contains("hibp"));
        assertTrue(text.contains("FOUND"));
    }
}
