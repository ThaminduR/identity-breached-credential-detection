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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.breach.detection.Outcome;
import org.wso2.carbon.identity.breach.detection.Credential;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * The verdict resolution table, row by row.
 * <p>
 * Every source decides for itself whether this organization wants it and what should happen when it cannot
 * answer, so these tests drive that through the sources rather than through a central policy.
 */
public class BreachEvaluationEngineTest {

    private static final String TENANT = "carbon.super";

    private SourceRegistry registry;
    private BreachEvaluationEngine engine;

    @BeforeMethod
    public void setUp() {

        registry = new SourceRegistry();
        engine = new BreachEvaluationEngine(registry, 4, 500);
    }

    @Test
    public void aSourceThatIsNotEnabledIsNeverConsulted() {

        StubBreachSource local = StubBreachSource.source("localList", 100,
                c -> Outcome.FOUND).disabled();
        registry.bind(local);

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.ACCEPT);
        assertEquals(local.getCalls(), 0);
    }

    /**
     * With nothing bound at all the plan is empty. That is a legitimate state - it is what an organization
     * that has switched nothing on looks like - and it must accept rather than fail the write.
     */
    @Test
    public void nothingEnabledMeansTheCapabilityIsSimplyOff() {

        assertEquals(engine.evaluate(candidate(), TENANT), Decision.ACCEPT);
    }

    @Test
    public void anyFoundRefusesAsBreached() {

        registry.bind(StubBreachSource.source("localList", 100, c -> Outcome.NOT_FOUND));
        registry.bind(StubBreachSource.source("hibp", 500, c -> Outcome.FOUND));

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_BREACHED);
    }

    @Test
    public void allNotFoundAccepts() {

        registry.bind(StubBreachSource.source("localList", 100, c -> Outcome.NOT_FOUND));
        registry.bind(StubBreachSource.source("hibp", 500, c -> Outcome.NOT_FOUND));

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.ACCEPT);
    }

    @Test
    public void aSourceThatCannotAnswerAndAllowsIsAcceptedAndReportedDegraded() {

        registry.bind(StubBreachSource.source("localList", 100, c -> Outcome.NOT_FOUND));
        registry.bind(StubBreachSource.source("hibp", 500,
                c -> Outcome.UNAVAILABLE)
                );

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.ACCEPT);
    }

    @Test
    public void aSourceThatCannotAnswerAndDeniesRefusesAsUnverified() {

        registry.bind(StubBreachSource.source("localList", 100, c -> Outcome.NOT_FOUND));
        registry.bind(StubBreachSource.source("hibp", 500,
                c -> Outcome.UNAVAILABLE)
                .refusing());

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_UNVERIFIED);
    }

    @Test
    public void everySourceUnavailableWithAllowAcceptsButIsNotEnforcing() {

        registry.bind(StubBreachSource.source("hibp", 500,
                c -> Outcome.UNAVAILABLE)
                );

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.ACCEPT);
    }


    @Test
    public void theCheapSourceRunsFirstAndAMatchStopsTheRest() {

        StubBreachSource local = StubBreachSource.source("localList", 100,
                c -> Outcome.FOUND);
        StubBreachSource remote = StubBreachSource.source("hibp", 500, c -> Outcome.NOT_FOUND);
        registry.bind(remote);
        registry.bind(local);

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_BREACHED);
        assertEquals(local.getCalls(), 1);
        assertEquals(remote.getCalls(), 0, "A match must end the evaluation before any network call.");
    }

    @Test
    public void anErrorInsideOneSourceIsContainedToThatSource() {

        StubBreachSource broken = StubBreachSource.source("broken", 100,
                c -> Outcome.NOT_FOUND).throwing(new IllegalStateException("connector defect"));
        StubBreachSource healthy = StubBreachSource.source("healthy", 200,
                c -> Outcome.FOUND);
        registry.bind(broken);
        registry.bind(healthy);

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_BREACHED);
        assertEquals(healthy.getCalls(), 1);
    }

    @Test
    public void aSourceThatCannotSayWhetherItIsEnabledIsSkippedRatherThanFailingTheWrite() {

        registry.bind(StubBreachSource.source("broken", 100, c -> Outcome.FOUND)
                .brokenIsEnabled(new IllegalStateException("configuration store down")));
        registry.bind(StubBreachSource.source("healthy", 200, c -> Outcome.NOT_FOUND));

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.ACCEPT);
    }

    @Test
    public void aRemoteSourceThatOverrunsItsBudgetIsUnavailableNotClean() {

        registry.bind(StubBreachSource.source("slow", 500, c -> Outcome.NOT_FOUND)
                .slow(2000).refusing());

        long started = System.currentTimeMillis();
        Decision result = engine.evaluate(candidate(), TENANT);
        long elapsed = System.currentTimeMillis() - started;

        assertEquals(result, Decision.REFUSE_UNVERIFIED);
        assertTrue(elapsed < 1500, "The call must be bounded by the timeout, not by the source. Took " + elapsed);
    }

    @Test
    public void theCredentialIsClearedOnceEverySourceHasAnswered() {

        registry.bind(StubBreachSource.source("localList", 100, c -> Outcome.NOT_FOUND));
        Credential candidate = candidate();

        engine.evaluate(candidate, TENANT);

        assertTrue(candidate.isCleared());
    }

    @Test
    public void aTimedOutCallLeavesTheCredentialAloneRatherThanCorruptingIt() {

        registry.bind(StubBreachSource.source("slow", 500, c -> Outcome.NOT_FOUND).slow(2000));
        Credential candidate = candidate();

        engine.evaluate(candidate, TENANT);

        assertTrue(!candidate.isCleared());
    }

    private Credential candidate() {

        return new Credential("Password@1".toCharArray());
    }
}
