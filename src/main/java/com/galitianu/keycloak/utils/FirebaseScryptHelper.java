package com.galitianu.keycloak.utils;

import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.credential.PasswordCredentialModel;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class FirebaseScryptHelper {
    private static final Logger LOG = Logger.getLogger(FirebaseScryptHelper.class);

    private static final Charset CHARSET = StandardCharsets.UTF_8;
    private static final String CIPHER = "AES/CTR/NoPadding";

    private FirebaseScryptHelper() {
        throw new IllegalStateException("Helper class");
    }

    public static boolean verifyPassword(String passwd, PasswordCredentialModel credential)
            throws GeneralSecurityException, IOException {
        String storedEncodedPassword = credential.getPasswordSecretData().getValue();
        byte[] salt = credential.getPasswordSecretData().getSalt();
        MultivaluedHashMap<String, String> additionalParameters = credential.getPasswordCredentialData().getAdditionalParameters();

        FirebaseScryptEncodingUtils.FirebaseScryptParameters scryptParameters =
                FirebaseScryptEncodingUtils.extractScryptParametersFromCredentials(storedEncodedPassword, additionalParameters);

        // Use the combined function to compute the final encrypted hash
        String computedEncodedPassword = hashWithSaltAndEncrypt(
                passwd,
                salt,
                scryptParameters.getSaltSeparator(),
                scryptParameters.getRounds(),
                scryptParameters.getMemCost(),
                scryptParameters.getSignerKey()
        );

        return storedEncodedPassword.equals(computedEncodedPassword);
    }

//    public static byte[] hashWithSalt(String passwd, byte[] decodedSalt, String saltSep, int rounds, int memcost)
//            throws GeneralSecurityException, IOException {
//        int N = 1 << memcost;
//        int p = 1;
//
//        byte[] decodedSaltSepBytes = org.keycloak.common.util.Base64.decode(saltSep);
//
//        byte[] saltConcat = new byte[decodedSalt.length + decodedSaltSepBytes.length];
//        System.arraycopy(decodedSalt, 0, saltConcat, 0, decodedSalt.length);
//        System.arraycopy(decodedSaltSepBytes, 0, saltConcat, decodedSalt.length, decodedSaltSepBytes.length);
//
//        return com.lambdaworks.crypto.SCrypt.scrypt(
//                passwd.getBytes(StandardCharsets.US_ASCII),
//                saltConcat, N, rounds, p, 64
//        );
//    }

    public static String hashWithSaltAndEncrypt(String passwd, byte[] salt, String saltSep, int rounds, int memcost, String signerKey)
            throws GeneralSecurityException, IOException {
        if (passwd == null) {
            throw new IllegalArgumentException("Password can't be null");
        }

        // Compute scrypt parameters
        int N = 1 << memcost;
        int p = 1;

        // Decode the salt separator and concatenate it with the salt
        byte[] decodedSaltSepBytes = org.keycloak.common.util.Base64.decode(saltSep);
        byte[] saltConcat = new byte[salt.length + decodedSaltSepBytes.length];
        System.arraycopy(salt, 0, saltConcat, 0, salt.length);
        System.arraycopy(decodedSaltSepBytes, 0, saltConcat, salt.length, decodedSaltSepBytes.length);

        byte[] scryptHash = com.lambdaworks.crypto.SCrypt.scrypt(
                passwd.getBytes(StandardCharsets.US_ASCII),
                saltConcat,
                N,
                rounds,
                p,
                64  // Derived key length
        );

        // AES encryption step
        byte[] signerBytes = Base64.getDecoder().decode(signerKey);
        byte[] cipherTextBytes = encrypt(signerBytes, scryptHash);

        // Return the final, encrypted, Base64-encoded hash
        return Base64.getEncoder().encodeToString(cipherTextBytes);
    }

    public static byte[] encrypt(byte[] signer, byte[] derivedKey) {
        try {
            Key key = new SecretKeySpec(derivedKey, 0, 32, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
            Cipher c = Cipher.getInstance(CIPHER);
            c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            return c.doFinal(signer);
        } catch (Exception ex) {
            LOG.error("Error during encryption", ex);
            return null;
        }
    }


    public static byte[] getSalt(int saltLength) {
        LOG.debugf("Generating salt with length '%d'.", saltLength);
        byte[] buffer = new byte[saltLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;

    }
}
