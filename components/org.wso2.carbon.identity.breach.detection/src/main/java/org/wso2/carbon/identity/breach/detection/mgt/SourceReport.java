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

package org.wso2.carbon.identity.breach.detection.mgt;

import org.wso2.carbon.identity.breach.source.Capability;
import org.wso2.carbon.identity.breach.source.Descriptor;
import org.wso2.carbon.identity.breach.source.FailureAction;
import org.wso2.carbon.identity.breach.source.PropertyDescriptor;
import org.wso2.carbon.identity.breach.source.SourceStatus;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * One installed source as the administrator surface renders it.
 * <p>
 * The source's own SPI objects are carried through rather than copied into a parallel shape: the copy would add
 * a second place for the same fact to be wrong, and every one of these types is already public. Only sources
 * that are actually bound appear, so <em>installed</em> needs no field - {@link #isEnabled()} against
 * {@link SourceStatus#getState()} is the whole of the actionable state.
 */
public final class SourceReport {

    private final String id;
    private final boolean enabled;
    private final int priority;
    private final Descriptor descriptor;
    private final SourceStatus status;
    private final Set<Capability> capabilities;
    private final List<PropertyDescriptor> properties;
    private final FailureAction failureAction;
    private final SourceStats stats;

    public SourceReport(String id, boolean enabled, int priority, Descriptor descriptor, SourceStatus status,
                        Set<Capability> capabilities, List<PropertyDescriptor> properties,
                        FailureAction failureAction, SourceStats stats) {

        this.id = id;
        this.enabled = enabled;
        this.priority = priority;
        this.descriptor = descriptor;
        this.status = status;
        this.capabilities = Collections.unmodifiableSet(capabilities);
        this.properties = Collections.unmodifiableList(properties);
        this.failureAction = failureAction;
        this.stats = stats;
    }

    public String getId() {

        return id;
    }

    /**
     * @return whether this organization asked for the source. A source that is bound but not enabled is simply
     * available; the state on {@link #getStatus()} says nothing about whether it is being consulted.
     */
    public boolean isEnabled() {

        return enabled;
    }

    public int getPriority() {

        return priority;
    }

    /**
     * @return how the source presents itself: display name, description, vendor, documentation, privacy notice.
     */
    public Descriptor getDescriptor() {

        return descriptor;
    }

    /**
     * @return what the source reports about itself, including the facts that prove it is working.
     */
    public SourceStatus getStatus() {

        return status;
    }

    public Set<Capability> getCapabilities() {

        return capabilities;
    }

    /**
     * @return the settings the source declares. A secret renders write-only and is never returned as a value.
     */
    public List<PropertyDescriptor> getProperties() {

        return properties;
    }

    /**
     * @return what happens to a password this source cannot check.
     */
    public FailureAction getFailureAction() {

        return failureAction;
    }

    public SourceStats getStats() {

        return stats;
    }
}
