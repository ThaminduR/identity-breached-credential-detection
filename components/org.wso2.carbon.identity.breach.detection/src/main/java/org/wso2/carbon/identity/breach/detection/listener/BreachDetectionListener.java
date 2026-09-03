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
import org.wso2.carbon.identity.breach.detection.engine.Decision;
import org.wso2.carbon.identity.breach.detection.internal.BreachDetectionDataHolder;
import org.wso2.carbon.identity.breach.detection.util.BreachDetectionUtils;
import org.wso2.carbon.identity.breach.detection.Credential;
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
 * The single interception point.
 * <p>
 * Every password-setting path calls {@code AbstractUserStoreManager}, which runs an ordered listener chain
 * before writing. Intercepting there covers paths added later, including against a secondary user store.
 * <p>
 * Order 420 is after input validation at 3 and before the service extension at 10000.
 */
public class BreachDetectionListener extends AbstractIdentityUserOperationEventListener {

    private static final Log LOG = LogFactory.getLog(BreachDetectionListener.class);

    @Override
    public int getExecutionOrderId() {

        int order = getOrderId();
        // The sentinel getOrderId returns when identity.xml carries no declaration for this listener.
        return order == IdentityCoreConstants.EVENT_LISTENER_ORDER_ID
                ? BreachDetectionConstants.DEFAULT_LISTENER_ORDER : order;
    }

    @Override
    public boolean doPreAddUser(String userName, Object credential, String[] roleList,
                                Map<String, String> claims, String profile, UserStoreManager userStoreManager)
            throws UserStoreException {

        // Self-registration, administrative user creation, and invitation completion all arrive here.
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

        // Administrative reset, and the reset that completes a recovery flow.
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
        BreachEvaluationEngine engine = BreachDetectionDataHolder.getInstance().getEvaluationEngine();
        if (engine == null) {
            LOG.debug("Breach detection is not fully started yet. The credential write proceeds unchanged.");
            return true;
        }

        char[] chars = extract(credential);
        if (chars == null || chars.length == 0) {
            // Nothing to check. Composition rules own empty and malformed input.
            return true;
        }

        if (isExemptBulkWrite(currentFlow())) {
            return true;
        }

        // A copy, so clearing it after evaluation cannot corrupt the write that follows.
        Credential candidate = new Credential(Arrays.copyOf(chars, chars.length));

        // The engine owns the copy from here: it clears it before returning, or leaves it to the collector
        // when a source timed out and may still be reading it.
        Decision decision;
        try {
            decision = engine.evaluate(candidate, resolveTenantDomain(userStoreManager));
        } catch (Throwable t) {
            candidate.clear();
            // A defect in our own engine is a server fault, and must not masquerade as a policy decision.
            LOG.error("Breached password detection failed unexpectedly. The credential write is refused.", t);
            throw new UserStoreException("An internal error occurred while checking the password.");
        }

        switch (decision) {
            case REFUSE_BREACHED:
                throw policyRejection(BreachDetectionConstants.ERROR_CODE_BREACHED_PASSWORD,
                        BreachDetectionConstants.MESSAGE_KEY_BREACHED,
                        "This password has appeared in a known data breach. Choose a longer, unique password.");
            case REFUSE_UNVERIFIED:
                throw policyRejection(BreachDetectionConstants.ERROR_CODE_CANNOT_VERIFY,
                        BreachDetectionConstants.MESSAGE_KEY_CANNOT_VERIFY,
                        "This password could not be checked right now. Try again in a moment.");
            default:
                return true;
        }
    }

    /**
     * A client error carrying its reason, not a server fault. The wrapped {@code PolicyViolationException} is
     * what the recovery and self-registration paths recognise.
     */
    private UserStoreClientException policyRejection(String errorCode, String messageKey, String fallback) {

        String message = BreachDetectionUtils.getMessage(messageKey, fallback);
        return new UserStoreClientException(message, errorCode, new PolicyViolationException(message));
    }

    /**
     * A bulk import or migration-time write, which an operator can exempt so a migration does not pay a
     * network round trip per row or burn third-party quota on data that is already in the store.
     */
    private boolean isExemptBulkWrite(Flow flow) {

        return flow != null && flow.getName() == Flow.Name.BULK_RESOURCE_UPDATE
                && BreachDetectionConfig.getInstance().isBulkExempt();
    }


    private Flow currentFlow() {

        try {
            IdentityContext context = IdentityContext.getThreadLocalIdentityContext();
            return context == null ? null : context.getFlow();
        } catch (Throwable t) {
            LOG.debug("No identity context is available; falling back to the listener hook for the operation.");
            return null;
        }
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


    /**
     * The credential arrives as a {@link Secret} for listeners that handle secrets and as a character sequence
     * otherwise. Neither is turned into a {@code String} here.
     */
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
