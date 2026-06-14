package ui;

import model.ScanResult;
import model.Threat;
import model.ThreatLevel;
import engine.PortScanner;
import engine.ReputationChecker.ReputationResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class ResultPanel extends JPanel {

    private JTextArea outputArea;
    private JPanel    statsBar;
    private JLabel    riskLabel;
    private JLabel    reputationLabel;
    private JLabel    portsLabel;
    private JLabel    threatsLabel;

    private static final Color BG      = new Color(5, 5, 10);
    private static final Color SURFACE = new Color(12, 15, 22);
    private static final Color PANEL   = new Color(16, 20, 30);
    private static final Color ACCENT  = new Color(0, 255, 120);
    private static final Color ACCENT2 = new Color(0, 180, 255);
    private static final Color MUTED   = new Color(50, 80, 60);
    private static final Font  MONO    = new Font("Courier New", Font.PLAIN, 13);
    private static final Font  MONO_B  = new Font("Courier New", Font.BOLD, 13);
    private static final Font  MONO_SM = new Font("Courier New", Font.PLAIN, 11);
    private static final Font  MONO_LG = new Font("Courier New", Font.BOLD, 15);

    public ResultPanel() {
        setLayout(new BorderLayout(0, 0));
        setBackground(BG);
        setBorder(new EmptyBorder(0, 20, 0, 20));

        // Stats bar — 4 cards side by side
        statsBar = new JPanel(new GridLayout(1, 4, 8, 0));
        statsBar.setBackground(BG);
        statsBar.setBorder(new EmptyBorder(10, 0, 10, 0));

        riskLabel       = statCard("RISK LEVEL", "—",         new Color(60, 70, 60));
        reputationLabel = statCard("IP REPUTATION", "—",      new Color(40, 50, 70));
        portsLabel      = statCard("PORTS OPEN", "—",         new Color(40, 60, 80));
        threatsLabel    = statCard("THREATS", "—",            new Color(60, 40, 60));

        statsBar.add(wrapCard(riskLabel,       new Color(0, 255, 120)));
        statsBar.add(wrapCard(reputationLabel, new Color(0, 180, 255)));
        statsBar.add(wrapCard(portsLabel,      new Color(0, 180, 255)));
        statsBar.add(wrapCard(threatsLabel,    new Color(180, 80, 255)));

        // Output area
        outputArea = new JTextArea("// Scan results will appear here...\n");
        outputArea.setFont(MONO);
        outputArea.setBackground(PANEL);
        outputArea.setForeground(new Color(160, 220, 180));
        outputArea.setEditable(false);
        outputArea.setBorder(new EmptyBorder(14, 16, 14, 16));
        outputArea.setLineWrap(false);

        JScrollPane scroll = new JScrollPane(outputArea);
        scroll.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(20, 35, 25)));
        scroll.getViewport().setBackground(PANEL);

        add(statsBar, BorderLayout.NORTH);
        add(scroll,   BorderLayout.CENTER);
    }

    private JLabel statCard(String title, String value, Color bg) {
        JLabel l = new JLabel("<html><center><span style='font-size:9px;color:#507060'>"
            + title + "</span><br><b>" + value + "</b></center></html>");
        l.setFont(MONO_B);
        l.setForeground(ACCENT);
        l.setHorizontalAlignment(SwingConstants.CENTER);
        return l;
    }

    private JPanel wrapCard(JLabel label, Color borderColor) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(new Color(14, 18, 26));
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(borderColor.getRed()/5,
                borderColor.getGreen()/5, borderColor.getBlue()/5), 1),
            new EmptyBorder(10, 8, 10, 8)
        ));
        card.add(label, BorderLayout.CENTER);
        return card;
    }

    public void displayResult(ScanResult result, ReputationResult reputation) {
        int totalScanned = PortScanner.getPortMap().size();
        int open         = result.getOpenPorts();
        int closed       = totalScanned - open;

        long crit   = result.getThreats().stream().filter(t -> t.getLevel() == ThreatLevel.CRITICAL).count();
        long high   = result.getThreats().stream().filter(t -> t.getLevel() == ThreatLevel.HIGH).count();
        long med    = result.getThreats().stream().filter(t -> t.getLevel() == ThreatLevel.MEDIUM).count();
        long low    = result.getThreats().stream().filter(t -> t.getLevel() == ThreatLevel.LOW).count();

        // Update stat cards
        String riskShort = result.getOverallRisk().split(" ")[0];
        updateCard(riskLabel,       "RISK LEVEL",    riskShort,      getRiskColor(result.getOverallRisk()));
        updateCard(reputationLabel, "IP REPUTATION", reputation.isMalicious() ? "MALICIOUS" : reputation.getAbuseScore() > 0 ? "SUSPICIOUS" : "CLEAN", reputation.isMalicious() ? new Color(255,60,60) : ACCENT);
        updateCard(portsLabel,      "PORTS OPEN",    open + " / " + totalScanned, ACCENT2);
        updateCard(threatsLabel,    "THREATS",       crit + "C  " + high + "H  " + med + "M  " + low + "L", new Color(200, 100, 255));

        // Build output text
        StringBuilder sb = new StringBuilder();
        sb.append("┌─────────────────────────────────────────────────────────────────────────────────┐\n");
        sb.append("│  TARGET      : ").append(pad(result.getTargetIP(), 36)).append("│\n");
        sb.append("│  VERDICT     : ").append(pad(result.getOverallRisk(), 36)).append("│\n");
        sb.append("│  PORTS       : ").append(pad(open + " open  /  " + closed + " closed  /  " + totalScanned + " scanned", 36)).append("│\n");
        sb.append("│  REPUTATION  : ").append(pad(reputation.getSummary().length() > 36 ? reputation.getSummary().substring(0,36) : reputation.getSummary(), 36)).append("│\n");
        sb.append("│  ABUSE SCORE : ").append(pad(reputation.getAbuseScore() + "%", 36)).append("│\n");
        sb.append("└─────────────────────────────────────────────────────────────────────────────────┘\n\n");

        if (result.getThreats().isEmpty()) {
            sb.append("  ✔  No threat ports detected — system appears clean.\n");
        } else {
            sb.append("  THREATS DETECTED  (").append(result.getThreats().size()).append(" total)\n");
            sb.append("  ─────────────────────────────────────────────────────\n\n");
            for (Threat t : result.getThreats()) {
                sb.append("  [").append(t.getLevel()).append("]  Port ")
                  .append(t.getPort()).append("  —  ").append(t.getService()).append("\n");
                sb.append("  ↳  ").append(t.getDescription()).append("\n");
                sb.append("  ↳  ").append(t.getTimestamp()).append("\n\n");
            }
        }

        outputArea.setText(sb.toString());
        outputArea.setCaretPosition(0);
    }

    private void updateCard(JLabel label, String title, String value, Color color) {
        label.setText("<html><center><span style='font-size:9px;color:#507060'>"
            + title + "</span><br><b><font color='" + toHex(color) + "'>"
            + value + "</font></b></center></html>");
    }

    private String toHex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    private Color getRiskColor(String risk) {
        if (risk.startsWith("CRITICAL")) return new Color(255, 60, 60);
        if (risk.startsWith("HIGH"))     return new Color(255, 140, 0);
        if (risk.startsWith("MEDIUM"))   return new Color(255, 220, 0);
        if (risk.startsWith("LOW"))      return ACCENT2;
        return ACCENT;
    }

    private String pad(String s, int len) {
        if (s == null) s = "N/A";
        if (s.length() >= len) return s;
        return s + " ".repeat(len - s.length());
    }

    public void clearDisplay() {
        outputArea.setText("// Scan results will appear here...\n");
        updateCard(riskLabel,       "RISK LEVEL",    "—", ACCENT);
        updateCard(reputationLabel, "IP REPUTATION", "—", ACCENT2);
        updateCard(portsLabel,      "PORTS OPEN",    "—", ACCENT2);
        updateCard(threatsLabel,    "THREATS",       "—", new Color(200,100,255));
    }

    public void setText(String t) { outputArea.setText(t); }
}
