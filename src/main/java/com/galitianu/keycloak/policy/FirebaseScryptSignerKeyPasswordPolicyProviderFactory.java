package com.galitianu.keycloak.policy;

public class FirebaseScryptSignerKeyPasswordPolicyProviderFactory extends FirebaseScryptGenericPolicyProviderFactory{
    public static final String ID = "firebase-scryptSignerKey";
    public static final String DEFAULT_SIGNER_KEY = "8mEmGBeiL++ApT4jtpy6KJqpjG9vPNA+DKpf3n+mRbltux55Q2APu7jf5H1YsEwm4xNjIGno9jE1cck+BtMUow==";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName () {
        return "The public key of the signer";
    }

    @Override
    public String getDefaultConfigValue(){
        return DEFAULT_SIGNER_KEY;
    }
}
