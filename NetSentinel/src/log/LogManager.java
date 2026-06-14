package log;

import java.io.*;
import java.nio.file.*;

// Unit III: FileReader, FileWriter, IOException
public class LogManager {

    private static final String LOG_FILE = "netsentinel_log.txt";

    public static String readLog() {
        File f = new File(LOG_FILE);
        if (!f.exists()) return "No scan logs found yet.";

        StringBuilder sb = new StringBuilder();
        // Unit III: try-with-resources, BufferedReader
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (IOException e) {
            return "Error reading log: " + e.getMessage();
        }
        return sb.toString();
    }

    public static void clearLog() {
        try (FileWriter fw = new FileWriter(LOG_FILE, false)) {
            fw.write(""); // overwrite with empty
        } catch (IOException e) {
            System.err.println("[ERROR] Could not clear log: " + e.getMessage());
        }
    }

    public static boolean logExists() {
        return new File(LOG_FILE).exists();
    }
}
