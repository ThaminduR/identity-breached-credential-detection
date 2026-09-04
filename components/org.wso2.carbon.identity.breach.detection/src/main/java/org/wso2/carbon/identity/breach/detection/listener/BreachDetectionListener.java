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

package org.wso2.carbon.identity.breach.detection.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.breach.detection.config.BreachDetectionConfig;
import org.wso2.carbon.identity.breach.detection.constants.BreachDetectionConstants;
import org.wso2.carbon.identity.breach.detection.engine.BreachEvaluationEngine;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.internal.BreachDetectionDataHolder;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.mgt.policy.PolicyViolationException;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;
import java.util.Map;

/**
 * Intercepts every password write. Every password-setting path calls {@code AbstractUserStoreManager},
 * which runs an ordered listener chain first, so intercepting there also covers paths added later and
 * writes to a secondary user store.
 */
public class BreachDetectionListener extends AbstractIdentityUserOperationEventListener {

    private static final Log LOG = LogFactory.getLog(BreachDetectionListener.class);

    private final BreachDetectionConfig config;

    public BreachDetectionListener(BreachDetectionConfig config) {

        this.config = config;
    }

    @Override
    public int getExecutionOrderId() {

        int order = getOrderId();
        // The value getOrderId returns when identity.xml carries no declaration for this listener.
        return order == IdentityCoreConstants.EVENT_LISTENER_ORDER_ID
                ? BreachDetectionConstants.DEFAULT_LISTENER_ORDER : order;
    }

    @Override
    public boolean doPreAddUser(String userName, Object credential, String[] roleList,
                                Map<String, String> claims, String profile, UserStoreManager userStoreManager)
            throws UserStoreException {

        return check(credential, userStoreManager);
    }

    @Override
    public boolean doPreUpdateCredential(String userName, Object newCredential, Object oldCredential,
                                         UserStoreManager userStoreManager) throws UserStoreException {

        return check(newCredential, userStoreManager);
    }

    @Override
    public boolean doPreUpdateCredentialWithID(String userID, Object newCredential, Object oldCredential,
                                               UserStoreManager userStoreManager) throws UserStoreException {

        return check(newCredential, userStoreManager);
    }

    @Override
    public boolean doPreUpdateCredentialByAdmin(String userName, Object newCredential,
                                                UserStoreManager userStoreManager) throws UserStoreException {

        return check(newCredential, userStoreManager);
    }

    @Override
    public boolean doPreUpdateCredentialByAdminWithID(String userID, Object newCredential,
                                                      UserStoreManager userStoreManager)
            throws UserStoreException {

        return check(newCredential, userStoreManager);
    }

    private boolean check(Object credential, UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        if (isBulkImport()) {
            return true;
        }

        BreachEvaluationEngine engine = BreachDetectionDataHolder.getInstance().getEvaluationEngine();
        if (engine == null) {
            LOG.debug("Breach detection is not fully started yet. The credential write proceeds unchanged.");
            return true;
        }

        char[] chars = extract(credential);
        if (chars == null || chars.length == 0) {
            // Composition rules handle empty and malformed input.
            return true;
        }

        // A copy, because the engine clears it and the write that follows needs the original.
        Credential candidate = new Credential(Arrays.copyOf(chars, chars.length));

        Decision decision;
        try {
            decision = engine.evaluate(candidate, resolveTenantDomain(userStoreManager));
        } catch (Throwable t) {
            candidate.clear();
            // A defect in the engine is a server fault, not a policy decision, so the write is refused.
            LOG.error("Breached password detection failed unexpectedly. The credential write is refused.", t);
            throw new UserStoreException("An internal error occurred while checking the password.");
        }

        switch (decision) {
            case REFUSE_BREACHED:
                throw policyRejection(BreachDetectionConstants.ErrorMessages.ERROR_CODE_BREACHED_PASSWORD);
            case REFUSE_UNVERIFIED:
                throw policyRejection(BreachDetectionConstants.ErrorMessages.ERROR_CODE_CANNOT_VERIFY);
            default:
                return true;
        }
    }

    /**
     * A bulk import is not evaluated: its passwords are migrated rather than chosen, so the user cannot act
     * on a refusal.
     * <p>
     * This needs the server to set {@link Flow.Name#BULK_RESOURCE_UPDATE}. As of 7.3.0 the SCIM 2.0 bulk
     * endpoint sets no flow, so this returns false there and the import is evaluated.
     */
    private boolean isBulkImport() {

        Flow flow = currentFlow();
        return flow != null && flow.getName() == Flow.Name.BULK_RESOURCE_UPDATE;
    }

    private Flow currentFlow() {

        try {
            IdentityContext context = IdentityContext.getThreadLocalIdentityContext();
            return context == null ? null : context.getFlow();
        } catch (Throwable t) {
            LOG.debug("No identity context is available, so the write is not treated as a bulk import.");
            return null;
        }
    }

    /** The wrapped {@code PolicyViolationException} is what recovery and self-registration recognise. */
    private UserStoreClientException policyRejection(BreachDetectionConstants.ErrorMessages error) {

        return new UserStoreClientException(error.getMessage(), error.getCode(),
                new PolicyViolationException(error.getMessage()));
    }

    private String resolveTenantDomain(UserStoreManager userStoreManager) {

        try {
            int tenantId = userStoreManager.getTenantId();
            String domain = IdentityTenantUtil.getTenantDomain(tenantId);
            if (domain != null) {
                return domain;
            }
        } catch (Throwable t) {
            LOG.debug("Could not resolve the tenant from the user store manager.", t);
        }
        return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
    }

    /** Arrives as a {@link Secret} or a character sequence. Neither becomes a {@code String} here. */
    private char[] extract(Object credential) {

        if (credential == null) {
            return null;
        }
        if (credential instanceof Secret) {
            return ((Secret) credential).getChars();
        }
        if (credential instanceof char[]) {
            return (char[]) credential;
        }
        if (credential instanceof CharSequence) {
            CharSequence sequence = (CharSequence) credential;
            char[] chars = new char[sequence.length()];
            for (int i = 0; i < sequence.length(); i++) {
                chars[i] = sequence.charAt(i);
            }
            return chars;
        }
        LOG.debug("The credential arrived in an unrecognised form and was not evaluated.");
        return null;
    }

}
