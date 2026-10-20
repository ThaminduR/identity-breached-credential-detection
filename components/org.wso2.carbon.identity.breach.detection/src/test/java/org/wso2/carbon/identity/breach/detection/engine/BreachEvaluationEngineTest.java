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
import org.wso2.carbon.identity.breach.detection.internal.BreachDetectionDataHolder;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * The decision resolution table, row by row.
 */
public class BreachEvaluationEngineTest {

    private static final String TENANT = "carbon.super";

    private final BreachDetectionDataHolder holder = BreachDetectionDataHolder.getInstance();
    private BreachEvaluationEngine engine;

    @BeforeMethod
    public void setUp() {

        for (BreachSource bound : holder.getSources()) {
            holder.unbindSource(bound);
        }
        engine = new BreachEvaluationEngine();
    }

    @Test
    public void aSourceThatIsNotEnabledIsNeverConsulted() {

        StubBreachSource local = StubBreachSource.source("localList", 100,
                c -> Decision.REFUSE_BREACHED).disabled();
        holder.bindSource(local);

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.ACCEPT);
        assertEquals(local.getCalls(), 0);
    }

    @Test
    public void nothingEnabledMeansTheCapabilityIsSimplyOff() {

        assertEquals(engine.evaluate(candidate(), TENANT), Decision.ACCEPT);
    }

    @Test
    public void anyFoundRefusesAsBreached() {

        holder.bindSource(StubBreachSource.source("localList", 100, c -> Decision.ACCEPT));
        holder.bindSource(StubBreachSource.source("hibp", 500, c -> Decision.REFUSE_BREACHED));

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_BREACHED);
    }

    @Test
    public void allNotFoundAccepts() {

        holder.bindSource(StubBreachSource.source("localList", 100, c -> Decision.ACCEPT));
        holder.bindSource(StubBreachSource.source("hibp", 500, c -> Decision.ACCEPT));

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.ACCEPT);
    }

    @Test
    public void aSourceThatRefusesBecauseItCouldNotCheckRefusesAsUnverified() {

        holder.bindSource(StubBreachSource.source("localList", 100, c -> Decision.ACCEPT));
        holder.bindSource(StubBreachSource.source("hibp", 500, c -> Decision.REFUSE_UNVERIFIED));

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_UNVERIFIED);
    }

    @Test
    public void aBreachedVerdictWinsOverAnUnverifiedOneWhenItComesFirst() {

        holder.bindSource(StubBreachSource.source("localList", 100, c -> Decision.REFUSE_BREACHED));
        holder.bindSource(StubBreachSource.source("hibp", 500, c -> Decision.REFUSE_UNVERIFIED));

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_BREACHED);
    }

    @Test
    public void theCheapSourceRunsFirstAndAMatchStopsTheRest() {

        StubBreachSource local = StubBreachSource.source("localList", 100,
                c -> Decision.REFUSE_BREACHED);
        StubBreachSource remote = StubBreachSource.source("hibp", 500, c -> Decision.ACCEPT);
        holder.bindSource(remote);
        holder.bindSource(local);

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_BREACHED);
        assertEquals(local.getCalls(), 1);
        assertEquals(remote.getCalls(), 0, "A match must end the evaluation before any network call.");
    }

    @Test
    public void anErrorInsideOneSourceIsContainedToThatSource() {

        StubBreachSource broken = StubBreachSource.source("broken", 100,
                c -> Decision.ACCEPT).throwing(new IllegalStateException("connector defect"));
        StubBreachSource healthy = StubBreachSource.source("healthy", 200,
                c -> Decision.REFUSE_BREACHED);
        holder.bindSource(broken);
        holder.bindSource(healthy);

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.REFUSE_BREACHED);
        assertEquals(healthy.getCalls(), 1);
    }

    @Test
    public void aSourceThatCannotSayWhetherItIsEnabledIsSkippedRatherThanFailingTheWrite() {

        holder.bindSource(StubBreachSource.source("broken", 100, c -> Decision.REFUSE_BREACHED)
                .brokenIsEnabled(new IllegalStateException("configuration store down")));
        holder.bindSource(StubBreachSource.source("healthy", 200, c -> Decision.ACCEPT));

        Decision result = engine.evaluate(candidate(), TENANT);

        assertEquals(result, Decision.ACCEPT);
    }

    @Test
    public void theCredentialIsClearedOnceEverySourceHasAnswered() {

        holder.bindSource(StubBreachSource.source("localList", 100, c -> Decision.ACCEPT));
        Credential candidate = candidate();

        engine.evaluate(candidate, TENANT);

        assertTrue(candidate.isCleared());
    }

    private Credential candidate() {

        return new Credential("Password@1".toCharArray());
    }
}
