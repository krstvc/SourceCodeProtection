package srcprotect.certs;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import srcprotect.utils.Algorithms;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Handles gathering user credentials from files
 */
public class CredentialsManager {

    /**
     * Reads the certificate from the specified file
     *
     * @param location a place where the certificate is stored
     * @return a certificate generated from the file
     * @throws IOException          if an I/O error occurs while trying to read from file
     * @throws CertificateException if unable to read contents of the certificate file
     */
    public static X509Certificate getUserCertificate(File location) throws IOException, CertificateException {
        FileInputStream inputStream = new FileInputStream(location);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);

        inputStream.close();

        return certificate;
    }

    /**
     * Gets the encrypted key from the file and then decrypts it with the user's password
     *
     * @param password used to decrypt contents of the file
     * @param location a place where the key is stored
     * @return key pair generated from the file
     * @throws IOException if an I/O error occurs while trying to read from file
     */
    public static KeyPair getUserKey(String password, File location) throws IOException {
        PEMParser parser = new PEMParser(new FileReader(location));
        PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) parser.readObject();

        PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider());

        parser.close();

        return keyConverter.getKeyPair(encryptedKeyPair.decryptKeyPair(decryptorProvider));
    }

    /**
     * Generates the hash of the password along with the specified salt and then encodes the hash
     *
     * @param password user's password
     * @param salt     used to avoid generating same hash if two users happen to have the same passwords
     * @return Base64 encoded hash of the password
     * @throws NoSuchAlgorithmException if the algorithm is not supported
     */
    public static String getEncodedPasswordHashAsString(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(Algorithms.PASSWORD_HASH_ALGORITHM);

        byte[] hashedPassword = password.getBytes();

        /*
        * Hashing the password 1000 times in order to slow down the brute force attack
        * Does not affect the performance since hash is calculated very quickly
        */
        for (int i = 0; i < 1000; ++i) {
            digest.reset();
            digest.update(salt);
            digest.update(hashedPassword);
            hashedPassword = digest.digest();
        }

        return new String(Base64.getEncoder().encode(hashedPassword));
    }

}
