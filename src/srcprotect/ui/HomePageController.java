package srcprotect.ui;

import javafx.beans.binding.Bindings;
import javafx.beans.binding.BooleanBinding;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import srcprotect.certs.CertificateAuthority;
import srcprotect.certs.CredentialsManager;
import srcprotect.users.User;
import srcprotect.users.Users;
import srcprotect.utils.logging.CustomLogger;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.logging.Level;

/**
 * Controller of the home page
 */
public class HomePageController {

    @FXML
    private TextField usernameInput;

    @FXML
    private PasswordField passwordInput;

    @FXML
    private Button loginButton;

    @FXML
    private Button newAccountButton;

    @FXML
    private Label checkMarkLabel;

    private Label certificatePathLabel = new Label();

    /**
     * Initializes the UI components and forbids any actions until the Certificate Authority is initialized
     */
    @FXML
    public void initialize() {
        Task<Void> initializer = new Task<Void>() {
            @Override
            protected Void call() {
                CertificateAuthority.initialize();
                return null;
            }
        };
        new Thread(initializer).start();

        BooleanBinding fieldsNotFilled = Bindings.isEmpty(usernameInput.textProperty())
                .or(Bindings.isEmpty(passwordInput.textProperty()))
                .or(Bindings.isEmpty(certificatePathLabel.textProperty()));

        loginButton.disableProperty().bind(initializer.runningProperty().or(fieldsNotFilled));
        newAccountButton.disableProperty().bind(initializer.runningProperty());
    }


    /**
     * Opens a file selection window in order to enable user to select their own certificate
     */
    public void chooseCertificate() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a certificate");
        chooser.setInitialDirectory(new File(
                System.getProperty("user.home") + File.separator
                        + "Documents" + File.separator + "srcprotect"));
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Certificates", "*.cer", "*.crt")
        );
        File file = chooser.showOpenDialog(new Stage());

        if (file != null) {
            certificatePathLabel.setText(file.toString());
            checkMarkLabel.setVisible(true);
        }
    }

    /**
     * Checks the input of all the fields in order to authenticate the user
     */
    public void attemptLogin() {
        String username = usernameInput.getText();
        String password = passwordInput.getText();

        /* Check if a user with the specified username exists */
        if (!Users.getUsers().containsKey(username)) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Invalid username",
                    "User '" + username + "' does not exist, please enter your credentials using valid username"
            );
            usernameInput.clear();
            passwordInput.clear();
            return;
        }

        /* Generate hash of the entered password */
        User loggingUser = Users.getUsers().get(username);
        String encodedPasswordHash = null;
        try {
            encodedPasswordHash = CredentialsManager.getEncodedPasswordHashAsString(password, username.getBytes());
        } catch (NoSuchAlgorithmException exception) {
            CustomLogger.log(Level.WARNING, Arrays.toString(exception.getStackTrace()), exception);
        }

        /* Check if a password is valid */
        if (!loggingUser.getEncodedPasswordHash().equals(encodedPasswordHash)) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Unable to login",
                    "Invalid password entered"
            );
            passwordInput.clear();
            return;
        }

        /* Read details from the selected certificate file */
        X509Certificate cert;
        try {
            cert = CredentialsManager.getUserCertificate(new File(certificatePathLabel.getText()));
        } catch (CertificateException exception) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Unable to read certificate from file, might have been corrupt",
                    "Check log file for more details"
            );
            CustomLogger.log(Level.WARNING, "Unable to read certificate from file", exception);
            return;
        } catch (IOException exception) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Unable to open file",
                    "Check log file for more details"
            );
            CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to read from file", exception);
            return;
        }

        /* Check whether the selected certificate belongs to the specified user */
        String subjectName = (cert.getSubjectDN().getName().split(",")[1]).replaceFirst("CN=", "").trim();
        if (!username.equals(subjectName)) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Invalid certificate selected",
                    "Selected certificate does not belong to the specified user"
            );
            return;
        }

        /*Check if the selected certificate is valid*/
        try {
            cert.checkValidity();
            if (CertificateAuthority.getCRL().isRevoked(cert)) {
                PopUp.displayWarningInfo(
                        "Warning",
                        "Certificate is revoked",
                        CertificateAuthority.getCRL().getRevokedCertificate(cert).getRevocationReason().toString()
                );
                return;
            }
        } catch (CertificateNotYetValidException exception) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Certificate not yet valid",
                    "Check certificate details before using it"
            );
            return;
        } catch (CertificateExpiredException exception) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Certificate has expired",
                    "This certificate is no longer valid"
            );
            CertificateAuthority.revokeCertificate(cert, CRLReason.PRIVILEGE_WITHDRAWN);
            return;
        }

        try {
            Parent root = FXMLLoader.load(getClass().getResource("EncryptionWindow.fxml"));

            Stage stage = new Stage();
            stage.setTitle("SRCPROTECT");
            stage.setScene(new Scene(root));
            stage.initModality(Modality.APPLICATION_MODAL);
            stage.setResizable(false);
            stage.show();
            usernameInput.getScene().getWindow().hide();
        } catch (IOException exception) {
            CustomLogger.log(Level.WARNING, "Unable to open encryption/decryption mode window", exception);
        }
        EncryptionWindowController.loggedUser = Users.getUsers().get(username);
        EncryptionWindowController.loggedUser.loadKeyPair(password);
    }

    /**
     * Generates a new user if the fields have been filled correctly
     */
    public void createNewAccount() {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("NewAccountWindow.fxml"));

            Stage stage = new Stage();
            stage.setTitle("Create new account");
            stage.setScene(new Scene(root));
            stage.initModality(Modality.APPLICATION_MODAL);
            stage.setResizable(false);
            stage.show();
        } catch (NullPointerException exception) {
            PopUp.displayErrorInfo(
                    "Error",
                    "Unable to open account creation window",
                    "Check log file for more details"
            );
            CustomLogger.log(Level.WARNING, "Invalid argument forwarded to FXMLLoader, resource was null when attempted to load from it", exception);
        } catch (IOException exception) {
            PopUp.displayErrorInfo(
                    "Error",
                    "Unable to open account creation window",
                    "Check log file for more details"
            );
            CustomLogger.log(Level.WARNING, "An I/O error occurred, could not open fxml file to load the window", exception);
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

}
