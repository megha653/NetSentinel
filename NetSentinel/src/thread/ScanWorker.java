package thread;

import engine.PortScanner;
import engine.IANAPortLoader;
import engine.ReputationChecker;
import engine.ReputationChecker.ReputationResult;
import model.ScanResult;

import javax.swing.*;
import java.util.List;

// Unit III: Multithreading — implements Runnable, uses Thread Pool internally
public class ScanWorker implements Runnable {

    private String targetIP;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    private ScanCallback callback;
    private List<Integer> customPorts;
    private boolean fullScan;

    public interface ScanCallback {
        void onComplete(ScanResult result, ReputationResult reputation);
    }

    public ScanWorker(String targetIP, JLabel statusLabel, JProgressBar progressBar,
                      ScanCallback callback, List<Integer> customPorts, boolean fullScan) {
        this.targetIP    = targetIP;
        this.statusLabel = statusLabel;
        this.progressBar = progressBar;
        this.callback    = callback;
        this.customPorts = customPorts;
        this.fullScan    = fullScan;
    }

    @Override
    public void run() {
        updateStatus("Loading IANA port database ...");
        IANAPortLoader.load();   // fetch real-time port names from IANA
        updateStatus("IANA: " + IANAPortLoader.getLoadStatus());
        sleep(300);
        updateStatus("Initializing scan on " + targetIP + " ...");
        sleep(200);

        // Show progress bar
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(0);
            progressBar.setVisible(true);
            progressBar.setString(fullScan ? "Scanning all 65,535 ports..." : "Scanning 45 ports...");
        });

        PortScanner scanner = new PortScanner(targetIP);
        scanner.addCustomPorts(customPorts);
        scanner.setFullScan(fullScan);

        if (fullScan) {
            // Unit III: Progress callback using lambda
            scanner.setProgressCallback((done, total) -> {
                int pct = (int)((done / (double) total) * 100);
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(pct);
                    progressBar.setString("Scanning " + done + " / " + total + " ports...");
                });
                updateStatus("Scanning all ports — " + pct + "% complete...");
            });
        }

        updateStatus(fullScan ? "Full scan started — scanning all 65,535 ports..." : "Probing known dangerous ports...");
        ScanResult result = scanner.scan();

        updateStatus("Checking IP reputation ...");
        ReputationResult reputation = ReputationChecker.check(targetIP);

        sleep(200);
        updateStatus("Scan complete — " + result.getOpenPorts() + " open port(s) found.");

        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(100);
            progressBar.setString("Scan complete!");
        });

        SwingUtilities.invokeLater(() -> callback.onComplete(result, reputation));
    }

    private void updateStatus(String msg) {
        SwingUtilities.invokeLater(() -> statusLabel.setText("> " + msg));
    }

    private void sleep(int ms) {
        try { Thread.sleep(ms); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
