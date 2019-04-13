package srcprotect.utils;

import java.io.File;
import java.io.IOException;

/**
 * Contains information about all the files used in the application
 */
@SuppressWarnings("ResultOfMethodCallIgnored")
public class Files {

    private static final File APP_ROOT_DIR = new File(
            System.getProperty("user.home") + File.separator
                    + "Documents" + File.separator
                    + "srcprotect"
    );
    private static final File CA_DIRECTORY = new File(
            APP_ROOT_DIR + File.separator
                    + "CA"
    );

    private static final File USERS_ROOT_DIR = new File(
            APP_ROOT_DIR + File.separator
                    + "Users"
    );

    private static final File USERS_FILE = new File(
            USERS_ROOT_DIR + File.separator
                    + "users.txt"
    );

    private static final File CRL_FILE = new File(
            CA_DIRECTORY + File.separator
                    + "CRL.crl"
    );

    private static final File LOG_FILE = new File(
            APP_ROOT_DIR + File.separator
                    + "log_file.log"
    );


    static {
        APP_ROOT_DIR.mkdirs();
        CA_DIRECTORY.mkdirs();
        USERS_ROOT_DIR.mkdirs();
        try {
            LOG_FILE.createNewFile();
            USERS_FILE.createNewFile();
        } catch (IOException exception) {
            exception.printStackTrace();
        }
    }


    /**
     * Getter for the CA certificate location
     *
     * @return location of the CA certificate on the file system
     */
    public static File getCACertificateLocation() {
        return new File(CA_DIRECTORY + File.separator + "CA.cer");
    }

    /**
     * Getter for the CA key location
     *
     * @return location of the CA key on the file system
     */
    public static File getCAKeyLocation() {
        return new File(CA_DIRECTORY + File.separator + "CA_key.pem");
    }

    /**
     * Getter for the file containing the list of all users
     *
     * @return location of the users file on the file system
     */
    public static File getUsersFileLocation() {
        return USERS_FILE;
    }

    /**
     * Gets the location of the directory for the specified user
     *
     * @param username user's username
     * @return location of the user's directory on the file system
     */
    public static File getUserDir(String username) {
        File userDir = new File(USERS_ROOT_DIR + File.separator + username);
        userDir.mkdirs();
        return userDir;
    }

    /**
     * Gets the location of the certificate file for the specified user
     *
     * @param username user's username
     * @return location of the user's certificate file on the file system
     */
    public static File getUserCertificateLocation(String username) {
        return new File(getUserDir(username) + File.separator + username + ".cer");
    }

    /**
     * Gets the location of the key file for the specified user
     *
     * @param username user's username
     * @return location of the user's key file on the file system
     */
    public static File getUserKeyLocation(String username) {
        return new File(getUserDir(username) + File.separator + username + "_key.pem");
    }

    /**
     * Getter for the CRL file location
     *
     * @return location of the CRL file on the file system
     */
    public static File getCRLFile() {
        return CRL_FILE;
    }

    /**
     * Getter for the log file location
     *
     * @return location of the log file on the file system
     */
    public static File getLogFile() {
        return LOG_FILE;
    }

}
