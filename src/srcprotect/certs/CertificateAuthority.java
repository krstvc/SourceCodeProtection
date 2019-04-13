package srcprotect.certs;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import srcprotect.ui.PopUp;
import srcprotect.utils.Algorithms;
import srcprotect.utils.Files;
import srcprotect.utils.logging.CustomLogger;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Level;

/**
 * A trusted party in the infrastructure, in charge of generating asymmetric keys and certificates for every user
 */
public class CertificateAuthority {

    private static KeyPair CAKeyPair;
    private static X509Certificate CACertificate;
    private static X500Name CAName;
    private static X509CRL CRL;

    /**
     * Tries to read Certificate Authority details from the file, creates a new one if unable to read
     */
    public static void initialize() {
        Security.addProvider(new BouncyCastleProvider());

        File CAKeyPairLocation = Files.getCAKeyLocation();
        File CACertificateLocation = Files.getCACertificateLocation();

        CAName = new X500Name(
                "CN=SRCPROTECT Root CA,O=SRCPROTECT"        //CN = Common Name, O = Organization
        );

        try {
            retrieveCACredentialsFromFiles(CAKeyPairLocation, CACertificateLocation);
        } catch (CertificateException exception) {
            CustomLogger.log(Level.WARNING, "Unable to read CA details from the files, they might be corrupt", exception);
            generateCACredentials();
        } catch (IOException exception) {
            CustomLogger.log(Level.WARNING, "An I/O error occurred while opening CA files, the file cannot be accessed properly", exception);
            generateCACredentials();
        }
    }

    /**
     * @return Certificate Revocation List - a list containing all of the revoked certificates
     */
    public static X509CRL getCRL() {
        return CRL;
    }

    /**
     * Loads CA key and certificate from designated files
     *
     * @param CAKeyPairLocation     location on the file system where the key is stored
     * @param CACertificateLocation location on the file system where the certificate is stored
     * @throws IOException          if an I/O error occurs while trying to read from files
     * @throws CertificateException if unable to load certificate from the file
     */
    private static void retrieveCACredentialsFromFiles(File CAKeyPairLocation, File CACertificateLocation)
            throws IOException, CertificateException {
        CAKeyPair = CredentialsManager.getUserKey("CAPasswordShouldBeStoredOtherwise", CAKeyPairLocation);
        CACertificate = CredentialsManager.getUserCertificate(CACertificateLocation);
        CRL = generateCRL();
    }

    /**
     * Generates a new key pair and uses it to generate a self-signed certificate. Generates a CRL and stores it on the file system
     */
    private static void generateCACredentials() {
        CAKeyPair = generateKeyPair();
        storeKey(
                Files.getCAKeyLocation(),
                "CAPasswordShouldBeStoredOtherwise",
                CAKeyPair
        );

        CACertificate = generateCertificate(
                "SRCPROTECT Root CA",
                CAKeyPair.getPublic(),
                true
        );
        CRL = generateCRL();
        storeCRL();
    }

    /**
     * Generates a key pair for the asymmetric algorithm used to digitally sign content
     *
     * @return 3072bit key, or null if the algorithm is not recognized
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(Algorithms.ASYMMETRIC_KEY_ALGORITHM);
            generator.initialize(3072);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException exception) {
            CustomLogger.log(Level.WARNING, "Specified algorithm does not exist, unable to generate key pair, returned null", exception);
            return null;
        }
    }

    /**
     * Generates a new X.509 certificate for the subject
     *
     * @param subjectName common name of the subject
     * @param publicKey   subject's public key
     * @param isCA        flag that indicates whether the subject is CA or not
     * @return new X.509 certificate signed by the CA
     */
    public static X509Certificate generateCertificate(String subjectName, PublicKey publicKey, boolean isCA) {
        Date notBefore = new Date(System.currentTimeMillis());

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(notBefore);
        if (isCA) {
            calendar.add(Calendar.YEAR, 3);
        } else {
            calendar.add(Calendar.YEAR, 1);
            if (calendar.getTime().after(CACertificate.getNotAfter())) {
                calendar.setTime(CACertificate.getNotAfter());
            }
        }

        Date notAfter = calendar.getTime();

        BigInteger serial = new BigInteger(Long.toString(notBefore.getTime()));

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                CAName,
                serial,
                notBefore,
                notAfter,
                new X500Name("O=SRCPROTECT, CN=" + subjectName),
                publicKey
        );

        try {
            BasicConstraints basicConstraints = new BasicConstraints(isCA);
            certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

            if (!isCA) {
                /*
                 * Users can use the certificate just for the specified purposes
                 */
                KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature);
                certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, keyUsage);
            }
        } catch (CertIOException exception) {
            CustomLogger.log(Level.WARNING, "Unable to add extensions to the certificate", exception);
        }

        ContentSigner contentSigner = null;
        try {
            contentSigner = new JcaContentSignerBuilder(Algorithms.DIGITAL_SIGNATURE_ALGORITHM).build(CAKeyPair.getPrivate());
        } catch (OperatorCreationException exception) {
            CustomLogger.log(Level.WARNING, "Unable to build an object for signing certificates", exception);
        }

        X509CertificateHolder certHolder = certBuilder.build(Objects.requireNonNull(contentSigner));

        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());

        if (isCA) {
            File location = Files.getCACertificateLocation();
            storeCertificate(location, certHolder);
        } else {
            File location = Files.getUserCertificateLocation(subjectName.replaceFirst("CN=", ""));
            storeCertificate(location, certHolder);
        }

        try {
            return certConverter.getCertificate(certHolder);
        } catch (CertificateException exception) {
            CustomLogger.log(Level.WARNING, "Unable to gather certificate from the certificate holder, returned null", exception);
            return null;
        }
    }

    /**
     * Generates a new Certificate Revocation List if it does not already exists, or updates the current one if it does exist
     *
     * @return new X.509 v2 CRL
     */
    private static X509CRL generateCRL() {
        Date date = new Date(System.currentTimeMillis());

        JcaX509v2CRLBuilder CRLBuilder = new JcaX509v2CRLBuilder(CACertificate, date);

        if (Files.getCRLFile().exists()) {
            try (FileInputStream input = new FileInputStream(Files.getCRLFile())) {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509CRL crl = (X509CRL) certFactory.generateCRL(input);
                Set revokedCerts = crl.getRevokedCertificates();
                if (revokedCerts != null && !revokedCerts.isEmpty()) {
                    for (Object entry : revokedCerts) {
                        X509CRLEntry CRLEntry = (X509CRLEntry) entry;
                        CRLBuilder.addCRLEntry(
                                CRLEntry.getSerialNumber(),
                                CRLEntry.getRevocationDate(),
                                CRLEntry.getRevocationReason().ordinal()
                        );
                    }
                }
            } catch (CertificateException exception) {
                CustomLogger.log(Level.WARNING, "Unable to get certificate details", exception);
            } catch (CRLException exception) {
                CustomLogger.log(Level.WARNING, "Unable to generate CRL", exception);
            } catch (IOException exception) {
                CustomLogger.log(Level.WARNING, "An I/O error occurred", exception);
            }
        }

        ContentSigner contentSigner = null;
        try {
            contentSigner = new JcaContentSignerBuilder(Algorithms.DIGITAL_SIGNATURE_ALGORITHM).build(CAKeyPair.getPrivate());
        } catch (OperatorCreationException exception) {
            CustomLogger.log(Level.WARNING, "Unable to create a content signing object", exception);
        }

        X509CRLHolder CRLHolder = CRLBuilder.build(Objects.requireNonNull(contentSigner));

        JcaX509CRLConverter CRLConverter = new JcaX509CRLConverter().setProvider(new BouncyCastleProvider());

        try {
            return CRLConverter.getCRL(CRLHolder);
        } catch (CRLException exception) {
            CustomLogger.log(Level.WARNING, "Unable to generate CRL", exception);
            return null;
        }
    }

    /**
     * Adds the certificate to the revocation list
     *
     * @param certificate      revoking certificate
     * @param revocationReason reason of revocation
     */
    public static void revokeCertificate(X509Certificate certificate, CRLReason revocationReason) {
        Date date = new Date(System.currentTimeMillis());

        JcaX509v2CRLBuilder CRLBuilder = new JcaX509v2CRLBuilder(CACertificate, date);

        Set revokedCerts = CRL.getRevokedCertificates();
        if (revokedCerts != null && !revokedCerts.isEmpty()) {
            for (Object entry : revokedCerts) {
                X509CRLEntry CRLEntry = (X509CRLEntry) entry;
                CRLBuilder.addCRLEntry(
                        CRLEntry.getSerialNumber(),
                        CRLEntry.getRevocationDate(),
                        CRLEntry.getRevocationReason().ordinal()
                );
            }
        }

        CRLBuilder.addCRLEntry(
                certificate.getSerialNumber(),
                date,
                revocationReason.ordinal()
        );

        ContentSigner contentSigner = null;
        try {
            contentSigner = new JcaContentSignerBuilder(Algorithms.DIGITAL_SIGNATURE_ALGORITHM).build(CAKeyPair.getPrivate());
        } catch (OperatorCreationException exception) {
            CustomLogger.log(Level.WARNING, "Unable to create a content signing object", exception);
        }

        X509CRLHolder CRLHolder = CRLBuilder.build(Objects.requireNonNull(contentSigner));

        JcaX509CRLConverter CRLConverter = new JcaX509CRLConverter().setProvider(new BouncyCastleProvider());

        try {
            CRL = CRLConverter.getCRL(CRLHolder);
        } catch (CRLException exception) {
            CustomLogger.log(Level.WARNING, "Unable to generate CRL", exception);
        }

        storeCRL();
    }

    /**
     * Stores a certificate to the specified location on the file system
     *
     * @param location   a place to store the certificate
     * @param certHolder holder of a certificate
     */
    private static void storeCertificate(File location, X509CertificateHolder certHolder) {
        try (PemWriter writer = new PemWriter(new FileWriter(location))) {
            writer.writeObject(new PemObject("CERTIFICATE", certHolder.toASN1Structure().getEncoded()));
        } catch (IOException exception) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Unable to store certificate",
                    "Check log file for more details"
            );
            CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to store certificate", exception);
        }
    }

    /**
     * Encrypts the key using the specified password and then stores it to the specified location on the file system
     *
     * @param location a place to store the key
     * @param password used to encrypt the key in order to avoid being visible to everyone
     * @param keyPair  a key to be stored
     */
    public static void storeKey(File location, String password, KeyPair keyPair) {
        try (JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(location))) {
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder(Algorithms.SYMMETRIC_KEY_ALGORITHM).build(password.toCharArray());
            JcaMiscPEMGenerator generator = new JcaMiscPEMGenerator(keyPair.getPrivate(), encryptor);
            writer.writeObject(generator);
        } catch (IOException exception) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Unable to store key",
                    "Check log file for more details"
            );
            CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to store key", exception);
        }
    }

    /**
     * Stores a Certificate Revocation List to the designated location on the file system
     */
    private static void storeCRL() {
        try (JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(Files.getCRLFile()))) {
            writer.writeObject(CRL);
        } catch (IOException exception) {
            CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to store CRL", exception);
        }
    }

}
