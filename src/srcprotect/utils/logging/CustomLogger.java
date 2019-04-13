package srcprotect.utils.logging;

import srcprotect.utils.Files;

import java.io.File;
import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Writes all the important information about the application running to the log file
 */
@SuppressWarnings("ResultOfMethodCallIgnored")
public class CustomLogger {

    private static Logger logger;

    /**
     * Creates new log file if it does not exist and adds a handler to the logger
     *
     * @throws IOException if an I/O error occurs
     */
    public static void setupLogger() throws IOException {
        logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

        File logFile = Files.getLogFile();
        if (!logFile.exists()) {
            logFile.getParentFile().mkdirs();
            logFile.createNewFile();
        }

        logger.setUseParentHandlers(false);
        Handler handler = new FileHandler(logFile.toString(), true);
        handler.setFormatter(new LogFormatter());
        logger.addHandler(handler);
    }

    /**
     * Writes the information about an incidence to the designated file
     *
     * @param level   level of severeness to be shown
     * @param message specific information about an incidence
     * @param thrown  the exception
     */
    public static void log(Level level, String message, Throwable thrown) {
        logger.log(level, message, thrown);
    }

}
