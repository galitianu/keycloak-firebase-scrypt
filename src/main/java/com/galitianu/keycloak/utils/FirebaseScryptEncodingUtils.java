package com.galitianu.keycloak.utils;

import com.galitianu.keycloak.credential.hash.FirebaseScryptPasswordHashProviderFactory;
import com.galitianu.keycloak.exceptions.FirebaseScryptRuntimeException;
import com.galitianu.keycloak.policy.FirebaseScryptMemCostPasswordPolicyProviderFactory;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordCredentialData;
import org.keycloak.models.credential.dto.PasswordSecretData;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class FirebaseScryptEncodingUtils {
    public static final String MEM_COST = "mem_cost";

    public static final String ROUNDS = "rounds";

    public static final String SALT_SEPARATOR = "base64_salt_separator";

    public static final String SIGNER_KEY = "base64_signer_key";

    public static PasswordCredentialModel createPasswordCredentialModel(byte[] salt, String encodedPassword,
                                                                        FirebaseScryptEncodingUtils.FirebaseScryptParameters firebaseScryptParameters) {

        PasswordCredentialData credentialData = new PasswordCredentialData(-1, FirebaseScryptPasswordHashProviderFactory.ID);
        PasswordSecretData secretData = new PasswordSecretData(encodedPassword, salt);
        MultivaluedHashMap<String, String> additionalParameters = credentialData.getAdditionalParameters();
        additionalParameters.putSingle(FirebaseScryptEncodingUtils.MEM_COST, Integer.toString(firebaseScryptParameters.getMemCost()));
        additionalParameters.putSingle(FirebaseScryptEncodingUtils.ROUNDS,
                Integer.toString(firebaseScryptParameters.getRounds()));
        additionalParameters.putSingle(FirebaseScryptEncodingUtils.SALT_SEPARATOR,
                firebaseScryptParameters.getSaltSeparator());
        additionalParameters.putSingle(FirebaseScryptEncodingUtils.SIGNER_KEY,
                firebaseScryptParameters.getSignerKey());

        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(credentialData,
                secretData);

        try {
            passwordCredentialModel.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            passwordCredentialModel.setSecretData(JsonSerialization.writeValueAsString(secretData));
            passwordCredentialModel.setType(PasswordCredentialModel.TYPE);
            return passwordCredentialModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static FirebaseScryptEncodingUtils.FirebaseScryptParameters extractScryptParametersFromCredentials(
            final String storedEncodedPassword,
            final MultivaluedHashMap<String, String> credentialParameters) {
        if (credentialParameters == null) {
            throw new IllegalArgumentException("Additional credential parameters are 'null'");
        }

        // Declare separate fields which are contained within the encoded password hash
        int memCost;
        int rounds;
        String saltSeparator;
        String signerKey;
        // Now attempt to extract all the parameters
        try {
            memCost = Integer.parseInt(
                    credentialParameters.getFirst(MEM_COST));
            rounds = Integer.parseInt(
                    credentialParameters.getFirst(ROUNDS));
            saltSeparator = credentialParameters.getFirst(SALT_SEPARATOR);
            signerKey = credentialParameters.getFirst(SIGNER_KEY);
        } catch (Exception e) {
            throw new FirebaseScryptRuntimeException(e.getMessage(), e);
        }
        // If we reach this point, all parameters were found and we return the
        // ScryptParameters carry object
        return new FirebaseScryptEncodingUtils.FirebaseScryptParameters(signerKey, saltSeparator, rounds, memCost);
    }


    public static class FirebaseScryptParameters {
        private final String signerKey;
        private final String saltSeparator;
        private final int rounds;
        private final int memCost;


        public FirebaseScryptParameters(String signerKey, String saltSeparator) {
            this(signerKey, saltSeparator, -1, FirebaseScryptMemCostPasswordPolicyProviderFactory.DEFAULT_MEM_COST);
        }

        public FirebaseScryptParameters(String signerKey, String saltSeparator, int rounds, int memCost) {
            this.signerKey = signerKey;
            this.saltSeparator = saltSeparator;
            this.rounds = rounds;
            this.memCost = memCost;

        }

        public String getSignerKey() {
            return signerKey;
        }

        public String getSaltSeparator() {
            return saltSeparator;
        }

        public int getRounds() {
            return rounds;
        }

        public int getMemCost() {
            return memCost;
        }
    }
}
