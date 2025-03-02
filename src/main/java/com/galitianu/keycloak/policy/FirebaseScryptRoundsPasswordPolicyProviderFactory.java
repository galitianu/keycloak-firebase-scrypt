package com.galitianu.keycloak.policy;

public class FirebaseScryptRoundsPasswordPolicyProviderFactory extends FirebaseScryptGenericPolicyProviderFactory{
    public static final String ID = "firebase-scryptRounds";
    public static final int DEFAULT_ROUNDS = 8;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName () {
        return "The blocksize parameter, which fine-tunes sequential memory read size and performance. An integer between 0 and 120000 (inclusive)";
    }

    @Override
    public String getDefaultConfigValue(){
        return String.valueOf(DEFAULT_ROUNDS);
    }
}
