package srcprotect.ui;

import javafx.application.Platform;
import javafx.scene.control.Alert;

/**
 * Displays some of the important information to the user in the form of the pop-up window
 */
@SuppressWarnings("WeakerAccess")
public class PopUp {

    /**
     * Displays brief information about an error that has occurred
     *
     * @param title       window title
     * @param headerText  error header
     * @param contentText further information
     */
    public static void displayErrorInfo(String title, String headerText, String contentText) {
        display(title, headerText, contentText, Alert.AlertType.ERROR);
    }

    /**
     * Displays a warning to the user
     *
     * @param title       window title
     * @param headerText  warning header
     * @param contentText further information
     */
    public static void displayWarningInfo(String title, String headerText, String contentText) {
        display(title, headerText, contentText, Alert.AlertType.WARNING);
    }

    /**
     * Displays brief information about a successful operation
     *
     * @param title       window title
     * @param headerText  confirmation header
     * @param contentText further information
     */
    public static void displayConfirmationInfo(String title, String headerText, String contentText) {
        display(title, headerText, contentText, Alert.AlertType.CONFIRMATION);
    }

    /**
     * In charge of instantiating different types of pop-up windows
     *
     * @param title       window title
     * @param headerText  header
     * @param contentText further information
     * @param alertType   type of a message to be displayed
     */
    private static void display(String title, String headerText, String contentText, Alert.AlertType alertType) {
        Thread displayed = new Thread(() ->
                Platform.runLater(() -> {
                    Alert alert = new Alert(alertType);
                    alert.setTitle(title);
                    alert.setHeaderText(headerText);
                    alert.setContentText(contentText);
                    alert.show();
                }));

        displayed.setDaemon(true);
        displayed.start();
    }

}