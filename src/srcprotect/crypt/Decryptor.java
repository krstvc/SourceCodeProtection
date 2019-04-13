package srcprotect.crypt;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.operator.OperatorCreationException;
import srcprotect.utils.logging.CustomLogger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.logging.Level;

/**
 * Used to decrypt digitally enveloped data and verify the signature of a sender
 */
@SuppressWarnings({"ConstantConditions", "unchecked"})
public class Decryptor {

    private KeyPair recipientKeyPair;
    private X509Certificate senderCertificate;

    public Decryptor(KeyPair recipientKeyPair, X509Certificate senderCertificate) {
        this.recipientKeyPair = recipientKeyPair;
        this.senderCertificate = senderCertificate;
    }

    /**
     * Gets the raw original plaintext data of the encrypted file
     *
     * @param content bytes from the encrypted file
     * @return original version of the file, or null if any error occurs
     */
    public byte[] decrypt(byte[] content) {
        byte[] decryptedContent = decryptContent(content);

        if (decryptedContent != null) {
            return verifyAndGetSignedContent(decryptedContent);
        }

        return null;
    }

    /**
     * Decrypts the content of the encrypted file using the same key used to encrypt it, which is contained in the header
     *
     * @param content bytes from the encrypted file
     * @return decrypted contents of the file, which contain the attached signature, or null if any error occurs
     */
    private byte[] decryptContent(byte[] content) {
        CMSEnvelopedData envelopedData;
        try {
            envelopedData = new CMSEnvelopedData(content);
        } catch (CMSException exception) {
            CustomLogger.log(Level.WARNING, "Encrypted file content might be corrupt", exception);
            return null;
        }

        Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
        KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
        JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(recipientKeyPair.getPrivate());

        try {
            return recipientInfo.getContent(recipient);
        } catch (CMSException exception) {
            CustomLogger.log(Level.WARNING, "Recipient information not valid", exception);
            return null;
        }

    }

    /**
     * Verifies the signature and gets raw data of the original file
     *
     * @param content decrypted contents of the file, which contain the attached signature
     * @return original file data, or null if any error occurs
     */
    private byte[] verifyAndGetSignedContent(byte[] content) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(content);
        ASN1InputStream asn1InputStream = new ASN1InputStream(inputStream);

        try {
            CMSSignedData signedData = new CMSSignedData(ContentInfo.getInstance(asn1InputStream.readObject()));

            SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();
            Collection<X509CertificateHolder> certs = signedData.getCertificates().getMatches(signerInfo.getSID());
            X509CertificateHolder certHolder = certs.iterator().next();

            /* If the specified sender is not the owner of the certificate contained in the file header, verification fails */
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
            if (!extractCN(certificate.getSubjectDN().getName()).equals(extractCN(senderCertificate.getSubjectDN().getName()))) {
                CustomLogger.log(Level.WARNING, "File was not signed by the selected sender", new Exception());
                return null;
            }

            if (signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder))) {
                return (byte[]) signedData.getSignedContent().getContent();
            }
        } catch (CMSException exception) {
            CustomLogger.log(Level.WARNING, "Unable to read signed data", exception);
        } catch (IOException exception) {
            CustomLogger.log(Level.WARNING, "An I/O error occurred while reading signed data", exception);
        } catch (OperatorCreationException exception) {
            CustomLogger.log(Level.WARNING, "Operator creation failed", exception);
        } catch (CertificateException exception) {
            CustomLogger.log(Level.WARNING, "Unable to read certificate", exception);
        }
        return null;
    }

    /**
     * Extracts the common name from the subject's distinguished name
     *
     * @param DN distinguished name of the subject
     * @return common name of the subject
     */
    private String extractCN(String DN) {
        String[] fields = DN.split(",");
        for (String field : fields) {
            if (field.startsWith("CN=")) {
                return field.trim();
            }
        }
        return null;
    }

}
