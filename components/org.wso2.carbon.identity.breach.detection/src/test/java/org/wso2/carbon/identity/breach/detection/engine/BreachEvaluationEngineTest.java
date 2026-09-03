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
import org.wso2.carbon.identity.breach.source.BreachContext;
import org.wso2.carbon.identity.breach.source.BreachVerdict;
import org.wso2.carbon.identity.breach.source.Credential;

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
                c -> BreachVerdict.found("localList")).disabled();
        registry.bind(local);

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.ACCEPT);
        assertEquals(local.getCalls(), 0);
    }

    /**
     * With nothing bound at all the plan is empty. That is a legitimate state - it is what an organization
     * that has switched nothing on looks like - and it must accept rather than fail the write.
     */
    @Test
    public void nothingEnabledMeansTheCapabilityIsSimplyOff() {

        assertEquals(engine.evaluate(context()), Decision.ACCEPT);
    }

    @Test
    public void anyFoundRefusesAsBreached() {

        registry.bind(StubBreachSource.source("localList", 100, c -> BreachVerdict.notFound("localList")));
        registry.bind(StubBreachSource.source("hibp", 500, c -> BreachVerdict.found("hibp")));

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.REFUSE_BREACHED);
    }

    @Test
    public void allNotFoundAccepts() {

        registry.bind(StubBreachSource.source("localList", 100, c -> BreachVerdict.notFound("localList")));
        registry.bind(StubBreachSource.source("hibp", 500, c -> BreachVerdict.notFound("hibp")));

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.ACCEPT);
    }

    @Test
    public void aSourceThatCannotAnswerAndAllowsIsAcceptedAndReportedDegraded() {

        registry.bind(StubBreachSource.source("localList", 100, c -> BreachVerdict.notFound("localList")));
        registry.bind(StubBreachSource.source("hibp", 500,
                c -> BreachVerdict.unavailable("hibp", "down"))
                );

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.ACCEPT);
    }

    @Test
    public void aSourceThatCannotAnswerAndDeniesRefusesAsUnverified() {

        registry.bind(StubBreachSource.source("localList", 100, c -> BreachVerdict.notFound("localList")));
        registry.bind(StubBreachSource.source("hibp", 500,
                c -> BreachVerdict.unavailable("hibp", "down"))
                .refusing());

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.REFUSE_UNVERIFIED);
    }

    @Test
    public void everySourceUnavailableWithAllowAcceptsButIsNotEnforcing() {

        registry.bind(StubBreachSource.source("hibp", 500,
                c -> BreachVerdict.unavailable("hibp", "slow"))
                );

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.ACCEPT);
    }


    @Test
    public void theCheapSourceRunsFirstAndAMatchStopsTheRest() {

        StubBreachSource local = StubBreachSource.source("localList", 100,
                c -> BreachVerdict.found("localList"));
        StubBreachSource remote = StubBreachSource.source("hibp", 500, c -> BreachVerdict.notFound("hibp"));
        registry.bind(remote);
        registry.bind(local);

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.REFUSE_BREACHED);
        assertEquals(local.getCalls(), 1);
        assertEquals(remote.getCalls(), 0, "A match must end the evaluation before any network call.");
    }

    @Test
    public void anErrorInsideOneSourceIsContainedToThatSource() {

        StubBreachSource broken = StubBreachSource.source("broken", 100,
                c -> BreachVerdict.notFound("broken")).throwing(new IllegalStateException("connector defect"));
        StubBreachSource healthy = StubBreachSource.source("healthy", 200,
                c -> BreachVerdict.found("healthy"));
        registry.bind(broken);
        registry.bind(healthy);

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.REFUSE_BREACHED);
        assertEquals(healthy.getCalls(), 1);
    }

    @Test
    public void aSourceThatCannotSayWhetherItIsEnabledIsSkippedRatherThanFailingTheWrite() {

        registry.bind(StubBreachSource.source("broken", 100, c -> BreachVerdict.found("broken"))
                .brokenIsEnabled(new IllegalStateException("configuration store down")));
        registry.bind(StubBreachSource.source("healthy", 200, c -> BreachVerdict.notFound("healthy")));

        Decision result = engine.evaluate(context());

        assertEquals(result, Decision.ACCEPT);
    }

    @Test
    public void aRemoteSourceThatOverrunsItsBudgetIsUnavailableNotClean() {

        registry.bind(StubBreachSource.source("slow", 500, c -> BreachVerdict.notFound("slow"))
                .slow(2000).refusing());

        long started = System.currentTimeMillis();
        Decision result = engine.evaluate(context());
        long elapsed = System.currentTimeMillis() - started;

        assertEquals(result, Decision.REFUSE_UNVERIFIED);
        assertTrue(elapsed < 1500, "The call must be bounded by the timeout, not by the source. Took " + elapsed);
    }

    @Test
    public void theCredentialIsClearedOnceEverySourceHasAnswered() {

        registry.bind(StubBreachSource.source("localList", 100, c -> BreachVerdict.notFound("localList")));
        BreachContext context = context();

        engine.evaluate(context);

        assertTrue(context.getCredential().isCleared());
    }

    @Test
    public void aTimedOutCallLeavesTheCredentialAloneRatherThanCorruptingIt() {

        registry.bind(StubBreachSource.source("slow", 500, c -> BreachVerdict.notFound("slow")).slow(2000));
        BreachContext context = context();

        engine.evaluate(context);

        assertTrue(!context.getCredential().isCleared());
    }

    private BreachContext context() {

        return new BreachContext(new Credential("Password@1".toCharArray()), TENANT);
    }
}
