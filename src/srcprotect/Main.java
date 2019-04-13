package srcprotect;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import srcprotect.utils.logging.CustomLogger;

/**
 * Entry point of the application
 */
public class Main extends Application {

    /**
     * Starts the application
     *
     * @param primaryStage landing page
     * @throws Exception if any kind of error occurs
     */
    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("ui/HomePage.fxml"));
        CustomLogger.setupLogger();

        primaryStage.setTitle("SRCPROTECT");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();
    }

    /**
     * Main method of the application
     *
     * @param args arguments
     */
    public static void main(String[] args) {
        launch(args);
    }

}
