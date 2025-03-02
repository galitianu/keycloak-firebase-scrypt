package com.galitianu.keycloak.policy;

public class FirebaseScryptMemCostPasswordPolicyProviderFactory extends FirebaseScryptGenericPolicyProviderFactory{
    public static final String ID = "firebase-scryptMemCost";
    public static final int DEFAULT_MEM_COST = 14;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "The memory cost. An integer between 1 and 14 (inclusive)";
    }

    @Override
    public String getDefaultConfigValue(){
        return String.valueOf(DEFAULT_MEM_COST);
    }
}
