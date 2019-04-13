package srcprotect.utils.logging;

import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * Enables writing log details in a readable and understandable format
 */
public class LogFormatter extends Formatter {

    /**
     * Formats the important details about an incidence
     *
     * @param record log record
     * @return string representation of a log record
     */
    @Override
    public String format(LogRecord record) {
        return "@LOG RECORD @ " + new Date(record.getMillis()) + System.getProperty("line.separator")
                + "    Thread: " + record.getThreadID() + System.getProperty("line.separator")
                + "    Source class: " + record.getSourceClassName() + System.getProperty("line.separator")
                + "    Source method: " + record.getSourceMethodName() + System.getProperty("line.separator")
                + "    ## " + record.getMessage() + " ##" + System.getProperty("line.separator")
                + System.getProperty("line.separator");
    }

}
