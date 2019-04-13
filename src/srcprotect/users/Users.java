package srcprotect.users;

import srcprotect.ui.PopUp;
import srcprotect.utils.Files;
import srcprotect.utils.logging.CustomLogger;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Level;

public class Users {

    private static HashMap<String, User> users = new HashMap<>();

    static {
        if (Files.getUsersFileLocation().exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(Files.getUsersFileLocation()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] fields = line.split("::::");
                    users.put(fields[0], new User(fields[0], fields[1]));
                }
            } catch (IOException exception) {
                CustomLogger.log(Level.WARNING, "An I/O error occurred, unable to load users", exception);
            }
        }
    }

    public static HashMap<String, User> getUsers() {
        return users;
    }

    public static void addUser(User user) {
        users.put(user.getUsername(), user);
    }

    public static void storeUsers() {
        try (FileWriter writer = new FileWriter(Files.getUsersFileLocation())) {
            for (User user : users.values()) {
                writer.write(
                        user.getUsername()
                                + "::::"
                                + user.getEncodedPasswordHash()
                                + System.getProperty("line.separator")
                );
                writer.flush();
            }
        } catch (IOException exception) {
            PopUp.displayWarningInfo(
                    "Warning",
                    "Unable to store users data",
                    "Check log file for more details"
            );
            CustomLogger.log(
                    Level.WARNING,
                    "An I/O error occurred, could not open users file to store data",
                    exception
            );
        }
    }

}
