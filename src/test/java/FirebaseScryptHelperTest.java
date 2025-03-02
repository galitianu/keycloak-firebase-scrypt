import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;

import com.galitianu.keycloak.credential.hash.FirebaseScryptPasswordHashProviderFactory;
import com.galitianu.keycloak.utils.FirebaseScryptEncodingUtils;
import com.galitianu.keycloak.utils.FirebaseScryptHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.credential.PasswordCredentialModel;


/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class FirebaseScryptHelperTest {

    private static final String ALGORITHM = FirebaseScryptPasswordHashProviderFactory.ID;

    private static final String SALT_SEPARATOR = "Bw==";
    private static final int ROUNDS = 8;
    private static final int MEM_COST = 14;
    private static final String SIGNER_KEY = "8mEmGBeiL++ApT4jtpy6KJqpjG9vPNA+DKpf3n+mRbltux55Q2APu7jf5H1YsEwm4xNjIGno9jE1cck+BtMUow==";

    private static byte[] salt;

    @BeforeEach
    public void generateSalt() {
        salt = FirebaseScryptHelper.getSalt(16);
    }

    @Test
    public void testScryptdHashAndVerifySamePassword() throws GeneralSecurityException, IOException {

        String rawPassword = "123456789";
        String hash = FirebaseScryptHelper.hashWithSaltAndEncrypt(
                rawPassword,
                salt,
                SALT_SEPARATOR,
                ROUNDS,
                MEM_COST,
                SIGNER_KEY);
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt,
                ROUNDS,hash);

        passwordCredentialModel.setSecretData(hash);

        setAdditionalParameters(
                passwordCredentialModel,
                SIGNER_KEY,
                SALT_SEPARATOR,
                ROUNDS,
                MEM_COST );
        boolean verified = FirebaseScryptHelper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }
//
    @Test
    public void testScryptdHashAndVerifyDifferentPassword() throws GeneralSecurityException, IOException {
        String rawPassword = "12345678";
        String hash = FirebaseScryptHelper.hashWithSaltAndEncrypt(
                rawPassword,
                salt,
                SALT_SEPARATOR,
                ROUNDS,
                MEM_COST,
                SIGNER_KEY);
        System.out.println(hash);
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt,
                ROUNDS, hash);
        passwordCredentialModel.setSecretData(hash);
        setAdditionalParameters(
                passwordCredentialModel,
                SIGNER_KEY,
                SALT_SEPARATOR,
                ROUNDS,
                MEM_COST );
        boolean verified = FirebaseScryptHelper.verifyPassword("gwerty123", passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

        @Test
        public void testScryptdVerifyPredefinedHash() throws GeneralSecurityException, IOException {
                String rawPassword = "12345678";
                String hash = "Vw5SfBICk5BfbbvXDw9IVVAhlz+0tDQ5mlbyoBqunaG/BVnHemntm9xf49zK3/enTKJAs2jehcXPXAu63czoFg==";
                PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
                                ALGORITHM,
                                Base64.getDecoder().decode("tr4ortO1COozoA=="),
                                ROUNDS,
                                hash);
                passwordCredentialModel.setSecretData(hash);
            setAdditionalParameters(
                    passwordCredentialModel,
                    SIGNER_KEY,
                    SALT_SEPARATOR,
                    ROUNDS,
                    MEM_COST );
                boolean verified = FirebaseScryptHelper.verifyPassword(rawPassword, passwordCredentialModel);
                Assertions.assertTrue(verified);
        }
//
//    @Test
//    public void testScryptdVerifyPredefinedWrongHash() {
//        String rawPassword = "supersecret";
//        String hash = "TMoKd43AKZSsDakIZf52DccKPvQQNUE//wmOl5gxvIM=";
//        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
//                ALGORITHM,
//                Base64.getDecoder().decode("kGPbRh+TIQIzn/A2DtHp5dZRMSrqRIrLlrOLPH8a/1A="),
//                DEFAULT_COST,
//                hash);
//        passwordCredentialModel.setSecretData(hash);
//        setAdditionalParameters(
//                passwordCredentialModel,
//                DEFAULT_COST,
//                DEFAULT_BLOCK_SIZE,
//                DEFAULT_PARALLELISM);
//        boolean verified = ScryptHelper.verifyPassword(rawPassword, passwordCredentialModel);
//        Assertions.assertFalse(verified);
//    }
//
//    @Test
//    public void testScryptdVerifyPredefinedWrongSalt() throws GeneralSecurityException, IOException {
//        String rawPassword = "supersecret";
//        String hash = "OaqIIbkVDDjH3OvyrkHAsUvIARzbhMD7REHMHmxjdPQ";
//        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
//                ALGORITHM,
//                salt,
//                DEFAULT_COST,
//                hash);
//        passwordCredentialModel.setSecretData(hash);
//        setAdditionalParameters(
//                passwordCredentialModel,
//                DEFAULT_COST,
//                DEFAULT_BLOCK_SIZE,
//                DEFAULT_PARALLELISM);
//        boolean verified = FirebaseScryptHelper.verifyPassword(rawPassword, passwordCredentialModel);
//        Assertions.assertFalse(verified);
//    }
//
//    @Test
//    public void testHashPasswordHashEmptyPassword() {
//        Assertions.assertThrows(
//                RuntimeException.class,
//                () -> ScryptHelper.hashPassword(
//                        null,
//                        salt,
//                        DEFAULT_COST,
//                        DEFAULT_BLOCK_SIZE,
//                        DEFAULT_PARALLELISM,
//                        ScryptHashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH));
//    }
//
//    @Test
//    public void testHashPasswordNoAlgorithm() {
//        String rawPassword = "novariantdefined";
//        String tamperedHash = "$$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
//        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt,
//                DEFAULT_COST, tamperedHash);
//        passwordCredentialModel.setSecretData(tamperedHash);
//        Assertions.assertThrows(RuntimeException.class,
//                () -> ScryptHelper.verifyPassword(rawPassword, passwordCredentialModel));
//    }
//
//    @Test
//    public void testHashPasswordNegativeIterations() {
//        int iterations = -1;
//        String rawPassword = "novariantdefined";
//        Executable exec = () -> ScryptHelper.hashPassword(
//                rawPassword,
//                salt,
//                iterations,
//                DEFAULT_BLOCK_SIZE,
//                DEFAULT_PARALLELISM,
//                ScryptHashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH);
//        Assertions.assertThrows(RuntimeException.class, exec);
//    }
//
//    @Test
//    public void testHashPasswordNoParallelism() {
//        int parallelism = 0;
//        String rawPassword = "novariantdefined";
//        Executable call = () -> ScryptHelper.hashPassword(
//                rawPassword,
//                salt,
//                DEFAULT_COST,
//                DEFAULT_BLOCK_SIZE,
//                parallelism,
//                ScryptHashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH);
//        Assertions.assertThrows(RuntimeException.class, call);
//    }
//
//    @Test
//    public void testHashPasswordNoMemory() {
//        int memory = 0;
//        String rawPassword = "novariantdefined";
//        Executable call = () -> ScryptHelper.hashPassword(
//                rawPassword,
//                salt,
//                DEFAULT_COST,
//                memory,
//                DEFAULT_PARALLELISM,
//                ScryptHashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH);
//        Assertions.assertThrows(RuntimeException.class, call);
//    }
//
//    @Test
//    public void testVerifyPasswordNonsenseData() {
//        String rawPassword = "testscryptid";
//        String hash = "nonsense";
//        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM,
//                "".getBytes(), DEFAULT_COST, hash);
//        passwordCredentialModel.setSecretData(hash);
//        Assertions.assertThrows(RuntimeException.class,
//                () -> ScryptHelper.verifyPassword(rawPassword, passwordCredentialModel));
//    }

    private static void setAdditionalParameters(PasswordCredentialModel passwordCredentialModel, String signerKey, String saltSep, int rounds, int memCost) {
        MultivaluedHashMap<String, String> additionalParameters =  passwordCredentialModel.getPasswordCredentialData()
                .getAdditionalParameters();
        additionalParameters.putSingle(FirebaseScryptEncodingUtils.MEM_COST, String.valueOf(memCost));
        additionalParameters.putSingle(FirebaseScryptEncodingUtils.ROUNDS,
                String.valueOf(rounds));
        additionalParameters.putSingle(FirebaseScryptEncodingUtils.SALT_SEPARATOR,
                saltSep);
        additionalParameters.putSingle(FirebaseScryptEncodingUtils.SIGNER_KEY,
                signerKey);
    }

}
