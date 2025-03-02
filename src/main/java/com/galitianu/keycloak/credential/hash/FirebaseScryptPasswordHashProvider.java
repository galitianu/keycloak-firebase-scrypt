package com.galitianu.keycloak.credential.hash;

import com.galitianu.keycloak.policy.FirebaseScryptMemCostPasswordPolicyProviderFactory;
import com.galitianu.keycloak.policy.FirebaseScryptRoundsPasswordPolicyProviderFactory;
import com.galitianu.keycloak.policy.FirebaseScryptSaltSeparatorPasswordPolicyProviderFactory;
import com.galitianu.keycloak.policy.FirebaseScryptSignerKeyPasswordPolicyProviderFactory;
import com.galitianu.keycloak.utils.FirebaseScryptEncodingUtils;
import com.galitianu.keycloak.utils.FirebaseScryptHelper;
import org.jboss.logging.Logger;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static com.galitianu.keycloak.utils.FirebaseScryptHelper.*;

public class FirebaseScryptPasswordHashProvider implements PasswordHashProvider {
    private static final Logger LOG = Logger.getLogger(FirebaseScryptPasswordHashProvider.class);

    private final String providerId;
    private final KeycloakSession session;

    public FirebaseScryptPasswordHashProvider(String providerId, KeycloakSession session) {
        this.providerId = providerId;
        this.session = session;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        return providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        try {
            // Generate a random salt
            byte[] salt = getSalt(16);
            FirebaseScryptEncodingUtils.FirebaseScryptParameters params = getConfiguredScryptParameters();

            // Call the helper that now does both hashing and encryption
            String finalHash = hashWithSaltAndEncrypt(
                    rawPassword,
                    salt,
                    params.getSaltSeparator(),
                    params.getRounds(),
                    params.getMemCost(),
                    params.getSignerKey()
            );

            return FirebaseScryptEncodingUtils.createPasswordCredentialModel(salt, finalHash, params);
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Failed to hash password", e);
        }
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        try {
            return FirebaseScryptHelper.verifyPassword(rawPassword, credential);
        } catch (GeneralSecurityException | IOException e) {
            LOG.error("Failed to verify password", e);
            return false;
        }
    }



    @Override
    public void close() {
    }

    private <T> T getDefaultValue(String providerId, T defaultValue) {
        T ret;
        try {
            ret = this.session.getContext().getRealm().getPasswordPolicy().getPolicyConfig(providerId);
        } catch (Exception e) {
            ret = defaultValue;
        }
        if (ret == null) ret = defaultValue;
        return ret;
    }

    private FirebaseScryptEncodingUtils.FirebaseScryptParameters getConfiguredScryptParameters() {
        return new FirebaseScryptEncodingUtils.FirebaseScryptParameters(
                getDefaultValue(FirebaseScryptSignerKeyPasswordPolicyProviderFactory.ID, FirebaseScryptSignerKeyPasswordPolicyProviderFactory.DEFAULT_SIGNER_KEY),
                getDefaultValue(FirebaseScryptSaltSeparatorPasswordPolicyProviderFactory.ID, FirebaseScryptSaltSeparatorPasswordPolicyProviderFactory.DEFAULT_SALT_SEPARATOR),
                getDefaultValue(FirebaseScryptRoundsPasswordPolicyProviderFactory.ID, FirebaseScryptRoundsPasswordPolicyProviderFactory.DEFAULT_ROUNDS),
                getDefaultValue(FirebaseScryptMemCostPasswordPolicyProviderFactory.ID, FirebaseScryptMemCostPasswordPolicyProviderFactory.DEFAULT_MEM_COST)
        );
    }
}