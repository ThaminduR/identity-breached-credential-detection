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

import org.wso2.carbon.identity.breach.source.BreachContext;
import org.wso2.carbon.identity.breach.source.BreachSource;
import org.wso2.carbon.identity.breach.source.BreachSourceException;
import org.wso2.carbon.identity.breach.source.BreachVerdict;
import org.wso2.carbon.identity.breach.source.FailureAction;
import org.wso2.carbon.identity.breach.source.PropertyDescriptor;
import org.wso2.carbon.identity.breach.source.SourceConfiguration;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * A source the engine has never seen, which is the only kind it ever gets.
 */
class StubBreachSource implements BreachSource {

    private final String id;
    private final int priority;
    private final Function<BreachContext, BreachVerdict> answer;
    private final AtomicInteger calls = new AtomicInteger();

    private boolean enabled = true;
    private FailureAction failureAction = FailureAction.ALLOW;
    private RuntimeException enabledFailure;
    private RuntimeException failure;
    private long delayMillis;

    private StubBreachSource(String id, int priority, Function<BreachContext, BreachVerdict> answer) {

        this.id = id;
        this.priority = priority;
        this.answer = answer;
    }

    static StubBreachSource source(String id, int priority, Function<BreachContext, BreachVerdict> answer) {

        return new StubBreachSource(id, priority, answer);
    }


    StubBreachSource disabled() {

        this.enabled = false;
        return this;
    }

    StubBreachSource onFailure(FailureAction action) {

        this.failureAction = action;
        return this;
    }

    StubBreachSource brokenIsEnabled(RuntimeException failure) {

        this.enabledFailure = failure;
        return this;
    }

    StubBreachSource throwing(RuntimeException failure) {

        this.failure = failure;
        return this;
    }

    StubBreachSource slow(long delayMillis) {

        this.delayMillis = delayMillis;
        return this;
    }

    int getCalls() {

        return calls.get();
    }

    @Override
    public String getId() {

        return id;
    }

    @Override
    public List<PropertyDescriptor> getProperties() {

        return Collections.emptyList();
    }

    @Override
    public void configure(SourceConfiguration configuration) {

    }

    @Override
    public int getPriority() {

        return priority;
    }



    @Override
    public boolean isEnabled(String tenantDomain) {

        if (enabledFailure != null) {
            throw enabledFailure;
        }
        return enabled;
    }

    @Override
    public FailureAction getFailureAction(String tenantDomain) {

        return failureAction;
    }

    @Override
    public BreachVerdict evaluate(BreachContext context) throws BreachSourceException {

        calls.incrementAndGet();
        if (delayMillis > 0) {
            // Deliberately ignores interruption: a connector that does not cooperate with cancellation is
            // exactly the case the engine has to survive without corrupting a call in flight.
            long until = System.currentTimeMillis() + delayMillis;
            while (System.currentTimeMillis() < until) {
                try {
                    Thread.sleep(10);
                } catch (InterruptedException ignored) {
                    // Swallowed on purpose.
                }
            }
        }
        if (failure != null) {
            throw failure;
        }
        return answer.apply(context);
    }
}
