package log;

import model.Threat;
import model.ScanResult;

import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

// Unit III: FileWriter, IOException handling
public class AlertLogger {

    private static final String LOG_FILE = "netsentinel_log.txt";

    // Unit II: static method
    public static void log(ScanResult result) {
        // Unit III: try-with-resources (FileWriter)
        try (FileWriter fw = new FileWriter(LOG_FILE, true)) {
            String separator = "=".repeat(60);
            String time = LocalDateTime.now()
                            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            fw.write(separator + "\n");
            fw.write("SCAN REPORT — " + time + "\n");
            fw.write("TARGET IP  : " + result.getTargetIP() + "\n");
            fw.write("OPEN PORTS : " + result.getOpenPorts() + "\n");
            fw.write("RISK LEVEL : " + result.getOverallRisk() + "\n");
            fw.write(separator + "\n");

            List<Threat> threats = result.getThreats();
            if (threats.isEmpty()) {
                fw.write("  No threats detected.\n");
            } else {
                for (Threat t : threats) {
                    fw.write("  " + t.toString() + "\n");
                }
            }

            fw.write(separator + "\n\n");
            System.out.println("[LOG] Report saved to " + LOG_FILE);

        } catch (IOException e) {
            System.err.println("[ERROR] Could not write log: " + e.getMessage());
        }
    }
}
