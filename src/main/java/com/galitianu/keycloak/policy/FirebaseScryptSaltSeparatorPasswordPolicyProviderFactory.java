package com.galitianu.keycloak.policy;

public class FirebaseScryptSaltSeparatorPasswordPolicyProviderFactory extends FirebaseScryptGenericPolicyProviderFactory{
    public static final String ID = "firebase-scryptSaltSeparator";
    public static final String DEFAULT_SALT_SEPARATOR = "Bw==";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName () {
        return "The separator to use when concatenating the hash with the salt";
    }

    @Override
    public String getDefaultConfigValue(){
        return DEFAULT_SALT_SEPARATOR;
    }
}
