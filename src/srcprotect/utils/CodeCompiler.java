package srcprotect.utils;

import srcprotect.utils.logging.CustomLogger;

import javax.tools.*;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;

/**
 * Compiles the code of the decrypted file and tries to run it
 */
public class CodeCompiler {

    /**
     * Creates a new thread to try to compile the given code
     *
     * @param file decrypted file location
     */
    public static void compileAndRun(File file) {
        new Thread(() -> {
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null);

            List<File> files = new ArrayList<>();
            files.add(file);

            Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjectsFromFiles(files);

            List<String> options = Arrays.asList("-classpath", System.getProperty("java.class.path"));

            DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();

            System.out.println("Compilation in progress...");
            if (!compiler.getTask(null, fileManager, diagnostics, options, null, compilationUnits).call()) {
                for (Diagnostic diagnostic : diagnostics.getDiagnostics()) {
                    String error = String.format("Compilation error: Line %d - %s%n", diagnostic.getLineNumber(), diagnostic.getMessage(null));
                    System.err.print(error);
                }
            } else {
                System.out.println("Compiled successfully" + System.getProperty("line.separator"));

                try {
                    String directory = file.toString().substring(0, file.toString().lastIndexOf(File.separator));
                    URLClassLoader classLoader = new URLClassLoader(new URL[]{new File(directory).toURI().toURL()});
                    Class<?> loadedClass = classLoader.loadClass(file.getName().replace(".java", ""));
                    loadedClass.getDeclaredMethod("main", new Class[]{String[].class}).invoke(null, new Object[]{null});
                } catch (ClassNotFoundException exception) {
                    CustomLogger.log(Level.WARNING, "Class not found", exception);
                } catch (NoSuchMethodException exception) {
                    CustomLogger.log(Level.WARNING, "Cannot find main method", exception);
                } catch (IllegalAccessException exception) {
                    CustomLogger.log(Level.WARNING, "Illegal access", exception);
                } catch (InvocationTargetException exception) {
                    CustomLogger.log(Level.WARNING, "Method invocation failed", exception);
                } catch (MalformedURLException exception) {
                    CustomLogger.log(Level.WARNING, "Unable to form URL", exception);
                }
            }
        }).start();
    }

}
