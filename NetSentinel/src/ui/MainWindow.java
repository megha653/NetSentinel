package ui;

import engine.PortScanner;
import log.AlertLogger;
import log.LogManager;
import model.ScanResult;
import thread.ScanWorker;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.List;

public class MainWindow extends JFrame {

    private static final Color BG       = new Color(5, 5, 10);
    private static final Color SURFACE  = new Color(12, 15, 22);
    private static final Color PANEL    = new Color(16, 20, 30);
    private static final Color ACCENT   = new Color(0, 255, 120);
    private static final Color ACCENT2  = new Color(0, 180, 255);
    private static final Color MUTED    = new Color(60, 90, 70);
    private static final Color RED      = new Color(255, 60, 60);
    private static final Color YELLOW   = new Color(255, 220, 50);
    private static final Color PURPLE   = new Color(180, 80, 255);
    private static final Font  MONO     = new Font("Courier New", Font.PLAIN, 13);
    private static final Font  MONO_B   = new Font("Courier New", Font.BOLD, 13);
    private static final Font  MONO_XL  = new Font("Courier New", Font.BOLD, 22);
    private static final Font  MONO_SM  = new Font("Courier New", Font.PLAIN, 11);

    private JTextField   ipField;
    private JTextField   customPortField;
    private JButton      scanButton;
    private JToggleButton fullScanToggle;
    private JLabel       statusLabel;
    private JProgressBar progressBar;
    private ResultPanel  resultPanel;

    public MainWindow() {
        setTitle("NetSentinel v2.0");
        setSize(920, 720);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(false);
        setBackground(BG);
        buildUI();
        setVisible(true);
    }

    private void buildUI() {
        JPanel root = new JPanel(new BorderLayout(0, 0));
        root.setBackground(BG);
        root.setBorder(new EmptyBorder(0, 0, 0, 0));
        root.add(buildTopBar(),    BorderLayout.NORTH);
        root.add(buildCenter(),    BorderLayout.CENTER);
        root.add(buildStatusBar(), BorderLayout.SOUTH);
        setContentPane(root);
    }

    // ── Top bar ─────────────────────────────────────────────────
    private JPanel buildTopBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(SURFACE);
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 2, 0, ACCENT),
            new EmptyBorder(14, 24, 14, 24)
        ));

        // Left: logo
        JPanel left = new JPanel(new GridLayout(2, 1, 0, 2));
        left.setBackground(SURFACE);
        JLabel title = new JLabel("◈  NETSENTINEL  v2.0");
        title.setFont(MONO_XL);
        title.setForeground(ACCENT);
        JLabel sub = new JLabel("LIVE NETWORK INTRUSION DETECTION  //  THREAT INTELLIGENCE  //  PORT RECON");
        sub.setFont(MONO_SM);
        sub.setForeground(MUTED);
        left.add(title);
        left.add(sub);

        // Right: status pill
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.setBackground(SURFACE);
        JLabel pill = new JLabel("  ● SYSTEM ONLINE  ");
        pill.setFont(MONO_SM);
        pill.setForeground(ACCENT);
        pill.setOpaque(true);
        pill.setBackground(new Color(0, 40, 20));
        pill.setBorder(BorderFactory.createLineBorder(ACCENT, 1));
        right.add(pill);

        bar.add(left,  BorderLayout.CENTER);
        bar.add(right, BorderLayout.EAST);
        return bar;
    }

    // ── Center ───────────────────────────────────────────────────
    private JPanel buildCenter() {
        JPanel center = new JPanel(new BorderLayout(0, 0));
        center.setBackground(BG);

        // Input section
        JPanel inputSection = new JPanel();
        inputSection.setLayout(new BoxLayout(inputSection, BoxLayout.Y_AXIS));
        inputSection.setBackground(BG);
        inputSection.setBorder(new EmptyBorder(16, 20, 10, 20));

        // Target row
        JPanel targetRow = new JPanel(new BorderLayout(10, 0));
        targetRow.setBackground(BG);
        targetRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));

        JLabel targetLabel = sideLabel("TARGET");
        ipField = new JTextField("localhost");
        styleField(ipField, ACCENT);
        scanButton = new JButton("▶  SCAN") {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                if (getModel().isPressed()) g2.setColor(ACCENT.darker());
                else if (getModel().isRollover()) g2.setColor(new Color(0, 210, 100));
                else g2.setColor(ACCENT);
                g2.fill(new RoundRectangle2D.Double(0, 0, getWidth(), getHeight(), 6, 6));
                g2.setColor(BG);
                g2.setFont(MONO_B);
                FontMetrics fm = g2.getFontMetrics();
                String txt = getText();
                g2.drawString(txt, (getWidth()-fm.stringWidth(txt))/2, (getHeight()+fm.getAscent()-fm.getDescent())/2);
                g2.dispose();
            }
        };
        scanButton.setFont(MONO_B);
        scanButton.setForeground(BG);
        scanButton.setPreferredSize(new Dimension(130, 42));
        scanButton.setBorderPainted(false);
        scanButton.setContentAreaFilled(false);
        scanButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        scanButton.setFocusPainted(false);

        targetRow.add(targetLabel, BorderLayout.WEST);
        targetRow.add(ipField,     BorderLayout.CENTER);
        targetRow.add(scanButton,  BorderLayout.EAST);

        // Custom ports row
        JPanel customRow = new JPanel(new BorderLayout(10, 0));
        customRow.setBackground(BG);
        customRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        customRow.setBorder(new EmptyBorder(8, 0, 0, 0));
        JLabel customLabel = sideLabel("PORTS  ");
        customPortField = new JTextField();
        customPortField.setToolTipText("e.g: 3000, 4200, 5000");
        styleField(customPortField, ACCENT2);
        JLabel hint = new JLabel("  + custom ports, comma separated");
        hint.setFont(MONO_SM);
        hint.setForeground(new Color(40, 60, 80));
        customRow.add(customLabel,     BorderLayout.WEST);
        customRow.add(customPortField, BorderLayout.CENTER);
        customRow.add(hint,            BorderLayout.EAST);

        // Toggle row
        JPanel toggleRow = new JPanel(new BorderLayout(10, 0));
        toggleRow.setBackground(BG);
        toggleRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        toggleRow.setBorder(new EmptyBorder(8, 0, 0, 0));

        fullScanToggle = new JToggleButton("  QUICK SCAN  [ 45 ports ]") {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                boolean on = isSelected();
                g2.setColor(on ? new Color(0, 30, 60) : new Color(15, 20, 30));
                g2.fill(new RoundRectangle2D.Double(0, 0, getWidth(), getHeight(), 6, 6));
                g2.setColor(on ? ACCENT2 : MUTED);
                g2.draw(new RoundRectangle2D.Double(0, 0, getWidth()-1, getHeight()-1, 6, 6));
                g2.setFont(MONO_B);
                g2.setColor(on ? ACCENT2 : new Color(80, 110, 90));
                String txt = getText();
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(txt, (getWidth()-fm.stringWidth(txt))/2, (getHeight()+fm.getAscent()-fm.getDescent())/2);
                g2.dispose();
            }
        };
        fullScanToggle.setFont(MONO_B);
        fullScanToggle.setContentAreaFilled(false);
        fullScanToggle.setBorderPainted(false);
        fullScanToggle.setFocusPainted(false);
        fullScanToggle.setCursor(new Cursor(Cursor.HAND_CURSOR));
        fullScanToggle.setPreferredSize(new Dimension(230, 32));
        fullScanToggle.addActionListener(e -> {
            if (fullScanToggle.isSelected()) fullScanToggle.setText("  FULL SCAN  [ 65,535 ports ]");
            else fullScanToggle.setText("  QUICK SCAN  [ 45 ports ]");
            fullScanToggle.repaint();
        });

        // Progress bar
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setFont(MONO_SM);
        progressBar.setForeground(ACCENT2);
        progressBar.setBackground(PANEL);
        progressBar.setBorder(BorderFactory.createLineBorder(new Color(20, 40, 60)));
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(100, 32));

        toggleRow.add(fullScanToggle, BorderLayout.WEST);
        toggleRow.add(progressBar,    BorderLayout.CENTER);

        inputSection.add(targetRow);
        inputSection.add(customRow);
        inputSection.add(toggleRow);

        // Results
        resultPanel = new ResultPanel();

        center.add(inputSection, BorderLayout.NORTH);
        center.add(resultPanel,  BorderLayout.CENTER);

        scanButton.addActionListener(e -> startScan());
        ipField.addActionListener(e -> startScan());

        return center;
    }

    // ── Status bar ───────────────────────────────────────────────
    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(SURFACE);
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(20, 35, 25)),
            new EmptyBorder(8, 20, 8, 20)
        ));

        statusLabel = new JLabel("> Ready — enter target IP or hostname");
        statusLabel.setFont(MONO_SM);
        statusLabel.setForeground(MUTED);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btnPanel.setBackground(SURFACE);
        btnPanel.add(makeButton("SAVE REPORT", ACCENT2));
        btnPanel.add(makeButton("VIEW LOGS",   PURPLE));
        btnPanel.add(makeButton("CLEAR",       RED));

        bar.add(statusLabel, BorderLayout.CENTER);
        bar.add(btnPanel,    BorderLayout.EAST);

        // wire buttons
        ((JButton)btnPanel.getComponent(0)).addActionListener(e -> saveReport());
        ((JButton)btnPanel.getComponent(1)).addActionListener(e -> viewLogs());
        ((JButton)btnPanel.getComponent(2)).addActionListener(e -> {
            resultPanel.clearDisplay();
            statusLabel.setText("> Cleared.");
            ipField.setText("");
            customPortField.setText("");
            progressBar.setVisible(false);
        });

        return bar;
    }

    // ── Helpers ──────────────────────────────────────────────────
    private JLabel sideLabel(String text) {
        JLabel l = new JLabel(text + " : ");
        l.setFont(MONO_B);
        l.setForeground(new Color(50, 100, 65));
        l.setPreferredSize(new Dimension(90, 38));
        return l;
    }

    private void styleField(JTextField f, Color accent) {
        f.setFont(MONO);
        f.setBackground(PANEL);
        f.setForeground(accent);
        f.setCaretColor(accent);
        f.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(new Color(accent.getRed()/6, accent.getGreen()/6, accent.getBlue()/6), 1),
            new EmptyBorder(4, 10, 4, 10)
        ));
    }

    private JButton makeButton(String text, Color color) {
        JButton btn = new JButton(text) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(getModel().isRollover() ? color.darker() : PANEL);
                g2.fill(new RoundRectangle2D.Double(0, 0, getWidth(), getHeight(), 6, 6));
                g2.setColor(color);
                g2.draw(new RoundRectangle2D.Double(0, 0, getWidth()-1, getHeight()-1, 6, 6));
                g2.setFont(MONO_SM);
                g2.setColor(color);
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(getText(), (getWidth()-fm.stringWidth(getText()))/2,
                    (getHeight()+fm.getAscent()-fm.getDescent())/2);
                g2.dispose();
            }
        };
        btn.setFont(MONO_SM);
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setPreferredSize(new Dimension(110, 28));
        return btn;
    }

    private void startScan() {
        String ip = ipField.getText().trim();
        if (ip.isEmpty()) { statusLabel.setText("> Please enter a target."); return; }

        List<Integer> customPorts = new ArrayList<>();
        String ct = customPortField.getText().trim();
        if (!ct.isEmpty()) {
            for (String p : ct.split(",")) {
                try {
                    int port = Integer.parseInt(p.trim());
                    if (port > 0 && port <= 65535) customPorts.add(port);
                } catch (NumberFormatException ignored) {}
            }
        }

        boolean doFull = fullScanToggle.isSelected();
        scanButton.setEnabled(false);
        resultPanel.clearDisplay();
        progressBar.setValue(0);
        progressBar.setVisible(true);

        ScanWorker worker = new ScanWorker(ip, statusLabel, progressBar,
            (result, reputation) -> {
                resultPanel.displayResult(result, reputation);
                scanButton.setEnabled(true);
            }, customPorts, doFull);

        new Thread(worker) {{ setDaemon(true); }}.start();
    }

    private void saveReport() {
        String ip = ipField.getText().trim();
        if (ip.isEmpty()) { statusLabel.setText("> Run a scan first."); return; }
        PortScanner ps = new PortScanner(ip);
        AlertLogger.log(ps.scan());
        statusLabel.setText("> Report saved to netsentinel_log.txt");
    }

    private void viewLogs() {
        JTextArea area = new JTextArea(LogManager.readLog());
        area.setFont(MONO_SM);
        area.setBackground(PANEL);
        area.setForeground(new Color(180, 255, 200));
        area.setEditable(false);
        JScrollPane scroll = new JScrollPane(area);
        scroll.setPreferredSize(new Dimension(740, 500));
        scroll.setBorder(BorderFactory.createLineBorder(ACCENT, 1));
        JDialog d = new JDialog(this, "// SCAN LOGS", true);
        d.getContentPane().setBackground(BG);
        d.add(scroll);
        d.pack();
        d.setLocationRelativeTo(this);
        d.setVisible(true);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(MainWindow::new);
    }
}
