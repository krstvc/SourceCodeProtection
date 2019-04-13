package srcprotect.crypt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import srcprotect.utils.Algorithms;
import srcprotect.utils.logging.CustomLogger;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;

/**
 * Used to secure file transfer by digitally signing the content and encrypting it with the digitally enveloped symmetric key
 */
public class Encryptor {

    private KeyPair senderKeyPair;
    private X509Certificate senderCert, recipientCert;

    public Encryptor(KeyPair senderKeyPair, X509Certificate senderCert, X509Certificate recipientCert) {
        this.senderKeyPair = senderKeyPair;
        this.senderCert = senderCert;
        this.recipientCert = recipientCert;
    }

    /**
     * Signs the content and then encrypts the attached signature with the specified algorithm
     *
     * @param content   raw data to be encrypted
     * @param algorithm symmetric algorithm used to encrypt the data
     * @return raw encrypted and signed data, or null if any error occurs
     */
    public byte[] encrypt(byte[] content, ASN1ObjectIdentifier algorithm) {
        byte[] signedContent = signContent(content);

        if (signedContent == null) {
            return null;
        }

        return encryptContent(signedContent, algorithm);
    }

    /**
     * Creates an attached digital signature of the content using the private key of the sender
     *
     * @param content content to be signed
     * @return raw attached digital signature, or null if any error occurs
     */
    private byte[] signContent(byte[] content) {
        CMSTypedData CMSData = new CMSProcessableByteArray(content);

        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();

        try {
            ContentSigner signer = new JcaContentSignerBuilder(Algorithms.DIGITAL_SIGNATURE_ALGORITHM).build(senderKeyPair.getPrivate());
            signedDataGenerator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                    ).build(signer, senderCert)
            );

            signedDataGenerator.addCertificate(new X509CertificateHolder(senderCert.getEncoded()));
            CMSSignedData signedData = signedDataGenerator.generate(CMSData, true);
            return signedData.getEncoded();
        } catch (OperatorCreationException exception) {
            CustomLogger.log(Level.WARNING, "Unable to create content signing object", exception);
        } catch (CertificateEncodingException exception) {
            CustomLogger.log(Level.WARNING, "Error occurred while adding signer info to signed data generator", exception);
        } catch (CMSException exception) {
            CustomLogger.log(Level.WARNING, "Unable to create certificate holder object", exception);
        } catch (IOException exception) {
            CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to load certificate", exception);
        }
        return null;
    }

    /**
     * Encrypts the signed content with the specified symmetric algorithm
     *
     * @param content   raw attached digital signature
     * @param algorithm symmetric algorithm used to encrypt the data
     * @return digitally enveloped attached signature of the data, or null if any error occurs
     */
    private byte[] encryptContent(byte[] content, ASN1ObjectIdentifier algorithm) {
        CMSEnvelopedDataGenerator envelopedDataGenerator = new CMSEnvelopedDataGenerator();

        try {
            JceKeyTransRecipientInfoGenerator recipientInfoGenerator = new JceKeyTransRecipientInfoGenerator(recipientCert);
            envelopedDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator);

            CMSTypedData data = new CMSProcessableByteArray(content);

            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(algorithm).setProvider("BC").build();

            CMSEnvelopedData envelopedData = envelopedDataGenerator.generate(data, encryptor);
            return envelopedData.getEncoded();
        } catch (CertificateEncodingException exception) {
            CustomLogger.log(Level.WARNING, "Error occurred while adding info to recipient data generator", exception);
        } catch (CMSException exception) {
            CustomLogger.log(Level.WARNING, "Unable to create encryptor object", exception);
        } catch (IOException exception) {
            CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to encrypt data", exception);
        }
        return null;
    }

}
