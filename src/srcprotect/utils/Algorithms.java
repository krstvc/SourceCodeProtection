package srcprotect.utils;

/**
 * Collection of the algorithms used in the application, with the exception of the symmetric algorithms used to encrypt file data
 */
public class Algorithms {

    public static final String ASYMMETRIC_KEY_ALGORITHM = "RSA";
    public static final String SYMMETRIC_KEY_ALGORITHM = "AES-256-CBC";

    public static final String PASSWORD_HASH_ALGORITHM = "SHA-224";

    public static final String DIGITAL_SIGNATURE_ALGORITHM = "SHA256withRSA";

}
