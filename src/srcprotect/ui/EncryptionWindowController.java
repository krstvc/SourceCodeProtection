package srcprotect.ui;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import srcprotect.certs.CredentialsManager;
import srcprotect.crypt.Decryptor;
import srcprotect.crypt.Encryptor;
import srcprotect.users.User;
import srcprotect.users.Users;
import srcprotect.utils.CodeCompiler;
import srcprotect.utils.Files;
import srcprotect.utils.logging.CustomLogger;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;

/**
 * Controller of the encryption window
 */
@SuppressWarnings({"SpellCheckingInspection", "WeakerAccess"})
public class EncryptionWindowController {

    @FXML
    private ComboBox<String> modeSelectionBox;

    @FXML
    private AnchorPane encryptionModePane, decryptionModePane;

    @FXML
    private Menu recipientMenu;

    @FXML
    private ComboBox<User> senderSelectionBox;

    @FXML
    private Label recipientLabel, plaintextFileLabel, algorithmLabel, senderLabel, cryptedFileLabel;

    @FXML
    private Button encryptAndSendButton, decryptButton;

    public static User loggedUser;

    /**
     * Initializes the UI components and prevents actions that would lead to errors
     */
    @FXML
    public void initialize() {
        modeSelectionBox.getItems().addAll(
                "Encryption mode",
                "Decryption mode"
        );

        for (User user : Users.getUsers().values()) {
            MenuItem item = new MenuItem(user.getUsername());
            recipientMenu.getItems().add(item);
            item.setOnAction(event -> recipientLabel.setText(((MenuItem) event.getSource()).getText()));
        }

        senderSelectionBox.getItems().addAll(Users.getUsers().values());

        decryptionModePane.prefWidthProperty().bind(encryptionModePane.widthProperty());
        decryptionModePane.prefHeightProperty().bind(encryptionModePane.heightProperty());

        encryptAndSendButton.disableProperty().bind(
                recipientLabel.textProperty().isEmpty()
                        .or(plaintextFileLabel.textProperty().isEmpty())
        );

        decryptButton.disableProperty().bind(
                senderLabel.textProperty().isEmpty()
                        .or(cryptedFileLabel.textProperty().isEmpty()));
    }

    /**
     * Switches between the encryption mode and the decryption mode
     */
    public void switchMode() {
        if (modeSelectionBox.getSelectionModel().getSelectedItem().equals("Encryption mode")) {
            encryptionModePane.setVisible(true);
            decryptionModePane.setVisible(false);
        } else {
            encryptionModePane.setVisible(false);
            decryptionModePane.setVisible(true);
        }
    }

    /**
     * Opens a file selection window in order to enable user to select a file they want to encrypt
     */
    public void selectFileToEncrypt() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a file to encrypt");
        chooser.setInitialDirectory(new File(
                System.getProperty("user.home") + File.separator
                        + "Documents" + File.separator + "srcprotect"));

        /* Only Java source files are available for encryption */
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Java source code", "*.java")
        );
        File file = chooser.showOpenDialog(new Stage());

        if (file != null) {
            plaintextFileLabel.setText(file.toString());
        }
    }

    /**
     * Opens a file selection window in order to enable user to select a file they want to decrypt
     */
    public void selectFileToDecrypt() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose encrypted file");
        chooser.setInitialDirectory(new File(
                System.getProperty("user.home") + File.separator
                        + "Documents" + File.separator + "srcprotect"));

        /* Encrypted files are in form of a simple binary file with extension .encrypted */
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Encrypted Java source code", "*.java.encrypted")
        );
        File file = chooser.showOpenDialog(new Stage());

        if (file != null) {
            cryptedFileLabel.setText(file.toString());
        }
    }

    /**
     * Changes the appearance of a button while holding it
     *
     * @param mouseEvent click on a button
     */
    public void clicked(MouseEvent mouseEvent) {
        ((Button) mouseEvent.getSource())
                .setStyle("-fx-background-color: #011a27; "
                        + "-fx-text-fill: #e6df44; "
                        + "-fx-border-color: #e6df44; "
                        + "-fx-border-radius: 5;");
    }

    /**
     * Resets the appearance of a button to default when released
     *
     * @param mouseEvent released button
     */
    public void clickFinished(MouseEvent mouseEvent) {
        ((Button) mouseEvent.getSource())
                .setStyle("-fx-background-color: #063852; "
                        + "-fx-text-fill: #e6df44; "
                        + "-fx-border-color:#e6df44; "
                        + "-fx-border-radius: 5;");
    }

    /**
     * Gathers the required information about sender and recipient, then encrypts the data of the selected file and sends it
     */
    public void encryptAndSendFile() {
        User sender = loggedUser;
        User recipient = Users.getUsers().get(recipientLabel.getText());
        KeyPair senderKeyPair = sender.getUserKeyPair();
        try {
            X509Certificate senderCertificate = CredentialsManager.getUserCertificate(
                    Files.getUserCertificateLocation(sender.getUsername())
            );
            X509Certificate receiverCertificate = CredentialsManager.getUserCertificate(
                    Files.getUserCertificateLocation(recipient.getUsername())
            );

            File file = new File(plaintextFileLabel.getText());
            byte[] bytesFromFile = java.nio.file.Files.readAllBytes(file.toPath());

            ASN1ObjectIdentifier algorithm;
            String algorithmID = algorithmLabel.getText();
            switch (algorithmID) {
                case "DES_EDE3_CBC":
                    algorithm = CMSAlgorithm.DES_EDE3_CBC;
                    break;
                case "AES128_CBC":
                    algorithm = CMSAlgorithm.AES128_CBC;
                    break;
                case "AES256_CBC":
                    algorithm = CMSAlgorithm.AES256_CBC;
                    break;
                case "CAMELLIA128_CBC":
                    algorithm = CMSAlgorithm.CAMELLIA128_CBC;
                    break;
                default:
                    algorithm = CMSAlgorithm.CAMELLIA256_CBC;
            }

            Encryptor encryptor = new Encryptor(senderKeyPair, senderCertificate, receiverCertificate);

            byte[] encrypted = encryptor.encrypt(bytesFromFile, algorithm);

            if (encrypted != null) {
                PopUp.displayConfirmationInfo(
                        "Success",
                        "Success",
                        "File encrypted successfully"
                );

                String fileName = file.getName() + ".encrypted";
                File encryptedFile = new File(Files.getUserDir(recipient.getUsername()) + File.separator + fileName);
                java.nio.file.Files.write(encryptedFile.toPath(), encrypted);
            } else {
                PopUp.displayErrorInfo(
                        "Error",
                        "Unable to encrypt the file",
                        "Check log file for more details"
                );
            }
        } catch (IOException exception) {
            CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to read from file", exception);
        } catch (CertificateException exception) {
            CustomLogger.log(Level.WARNING, "Unable to read certificate from file", exception);
        }

    }

    /**
     * Decrypts the content of the file generated through the encryption mode and runs it if possible
     */
    public void decryptAndRunFile() {
        User sender = Users.getUsers().get(senderLabel.getText());
        User recipient = loggedUser;
        KeyPair recipientKeyPair = recipient.getUserKeyPair();
        try {
            X509Certificate senderCert = CredentialsManager.getUserCertificate(
                    Files.getUserCertificateLocation(sender.getUsername())
            );

            File file = new File(cryptedFileLabel.getText());
            byte[] bytesFromFile = java.nio.file.Files.readAllBytes(file.toPath());

            Decryptor decryptor = new Decryptor(recipientKeyPair, senderCert);

            byte[] decrypted = decryptor.decrypt(bytesFromFile);

            if (decrypted != null) {
                PopUp.displayConfirmationInfo(
                        "Success",
                        "Success",
                        "File decrypted successfully"
                );

                String fileName = file.getName().replace(".encrypted", "");
                File decryptedFile = new File(Files.getUserDir(recipient.getUsername()) + File.separator + fileName);
                java.nio.file.Files.write(decryptedFile.toPath(), decrypted);

                CodeCompiler.compileAndRun(decryptedFile);
            } else {
                PopUp.displayErrorInfo(
                        "Error",
                        "Unable to decrypt the file",
                        "Check log file for more details"
                );
            }
        } catch (IOException exception) {
            CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to read from file", exception);
        } catch (CertificateException exception) {
            CustomLogger.log(Level.WARNING, "Unable to read certificate from file", exception);
        }

    }

    /**
     * Displays the algorithm selection choice
     *
     * @param actionEvent click on the menu item
     */
    public void setAlgorithm(ActionEvent actionEvent) {
        algorithmLabel.setText(((MenuItem) actionEvent.getSource()).getId());
    }

    /**
     * Displays the sender selection choice
     */
    public void selectSender() {
        senderLabel.setText(senderSelectionBox.getSelectionModel().getSelectedItem().getUsername());
    }

}
