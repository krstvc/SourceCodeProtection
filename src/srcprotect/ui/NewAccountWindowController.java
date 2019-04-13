package srcprotect.ui;

import javafx.beans.binding.Bindings;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import srcprotect.certs.CredentialsManager;
import srcprotect.users.User;
import srcprotect.users.Users;
import srcprotect.utils.logging.CustomLogger;

import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

/**
 * Controller of the new account window
 */
public class NewAccountWindowController {

    @FXML
    private TextField usernameInput;

    @FXML
    private PasswordField passwordInput;

    @FXML
    private PasswordField confirmPasswordInput;

    @FXML
    private Button submitButton;


    /**
     * Initializes the UI components and prevents actions that would lead to errors
     */
    @FXML
    public void initialize() {
        submitButton.disableProperty().bind(
                Bindings.isEmpty(usernameInput.textProperty())
                        .or(Bindings.isEmpty(passwordInput.textProperty()))
                        .or(Bindings.isEmpty(confirmPasswordInput.textProperty()))
        );
    }

    /**
     * Does all the required checks and generates a new account if everything was ok
     */
    public void attemptAccountCreation() {
        String username = usernameInput.getText();
        String password = passwordInput.getText();
        String confirmedPassword = confirmPasswordInput.getText();

        /* Check if the user with the specified username already exists */
        if (Users.getUsers().containsKey(username)) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "User '" + username + "' already exists",
                    "Enter your credentials using another username"
            );
            usernameInput.clear();
            passwordInput.clear();
            confirmPasswordInput.clear();
            return;
        }

        /* Check if the confirmation of the password equals the password */
        if (!password.equals(confirmedPassword)) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Passwords do not match",
                    "Please reenter your password"
            );
            passwordInput.clear();
            confirmPasswordInput.clear();
            return;
        }

        String encodedPasswordHash = null;
        try {
            encodedPasswordHash = CredentialsManager.getEncodedPasswordHashAsString(password, username.getBytes());
        } catch (NoSuchAlgorithmException exception) {
            CustomLogger.log(Level.WARNING, "Unable to get password hash, specified algorithm does not exist or is not supported", exception);
        }

        User newUser = new User(username, encodedPasswordHash);
        newUser.generateCredentials(password);

        Users.addUser(newUser);
        Users.storeUsers();

        PopUp.displayConfirmationInfo(
                "Success",
                "Success",
                "Account created successfully"
        );
        usernameInput.getScene().getWindow().hide();
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
