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

import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * A source the engine has never seen, which is the only kind it ever gets.
 */
class StubBreachSource implements BreachSource {

    private final String id;
    private final int priority;
    private final Function<Credential, Decision> answer;
    private final AtomicInteger calls = new AtomicInteger();

    private boolean enabled = true;
    private RuntimeException enabledFailure;
    private RuntimeException failure;

    private StubBreachSource(String id, int priority, Function<Credential, Decision> answer) {

        this.id = id;
        this.priority = priority;
        this.answer = answer;
    }

    static StubBreachSource source(String id, int priority, Function<Credential, Decision> answer) {

        return new StubBreachSource(id, priority, answer);
    }

    StubBreachSource disabled() {

        this.enabled = false;
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

    int getCalls() {

        return calls.get();
    }

    @Override
    public String getId() {

        return id;
    }

    @Override
    public int getPriority() {

        return priority;
    }

    @Override
    public void configure(SourceConfiguration configuration) {

    }

    @Override
    public boolean isEnabled(String tenantDomain) {

        if (enabledFailure != null) {
            throw enabledFailure;
        }
        return enabled;
    }

    @Override
    public Decision check(Credential credential, String tenantDomain) {

        calls.incrementAndGet();
        if (failure != null) {
            throw failure;
        }
        return answer.apply(credential);
    }
}
