package srcprotect.users;

import srcprotect.certs.CertificateAuthority;
import srcprotect.certs.CredentialsManager;
import srcprotect.utils.Files;
import srcprotect.utils.logging.CustomLogger;

import java.io.IOException;
import java.security.KeyPair;
import java.util.logging.Level;

/**
 * User of the application to whom the Certificate Authority gives the key pair and the certificate
 * in order to enable him to send and receive encrypted content
 */
public class User {

    private String username;
    private String encodedPasswordHash;

    private KeyPair userKeyPair;

    public User(String username, String encodedPasswordHash) {
        this.username = username;
        this.encodedPasswordHash = encodedPasswordHash;

        userKeyPair = null;
    }

    /**
     * Certificate Authority generates and signs user's key and certificate
     *
     * @param password password of a user
     */
    public void generateCredentials(String password) {
        new Thread(() -> {
            userKeyPair = CertificateAuthority.generateKeyPair();
            CertificateAuthority.storeKey(Files.getUserKeyLocation(username), password, userKeyPair);
            CertificateAuthority.generateCertificate(username, userKeyPair.getPublic(), false);
        }).start();
    }

    /**
     * Loads key from the designated file
     *
     * @param password password of a user
     */
    public void loadKeyPair(String password) {
        try {
            userKeyPair = CredentialsManager.getUserKey(password, Files.getUserKeyLocation(username));
        } catch (IOException exception) {
            CustomLogger.log(
                    Level.WARNING,
                    "Unable to load key from file",
                    exception
            );
        }
    }

    /**
     * Getter for the username
     *
     * @return user's username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Getter for the encoded password hash
     *
     * @return Base64 encoded hash of the user's password
     */
    public String getEncodedPasswordHash() {
        return encodedPasswordHash;
    }

    /**
     * Getter for the key pair
     *
     * @return user's key pair
     */
    public KeyPair getUserKeyPair() {
        return userKeyPair;
    }

    /**
     * Sets username as the string representation of the object
     *
     * @return user's username
     */
    @Override
    public String toString() {
        return username;
    }

}
