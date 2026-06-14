package engine;

import model.ScanResult;
import model.Threat;
import model.ThreatLevel;

import java.net.Socket;
import java.net.InetSocketAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

// Unit II: Inheritance — extends abstract Scanner
// Unit III: ExecutorService, Thread Pool, AtomicInteger
// Unit V:  Collections — Map, List, ConcurrentLinkedQueue
public class PortScanner extends Scanner {

    // Well-known dangerous ports with descriptions
    private static final Map<Integer, String[]> PORT_MAP = new LinkedHashMap<>();

    static {
        // Remote Access & File Transfer
        PORT_MAP.put(21,    new String[]{"FTP",           "File Transfer — credentials sent in plain text",    "HIGH"});
        PORT_MAP.put(22,    new String[]{"SSH",           "Secure Shell — brute-force target if exposed",      "MEDIUM"});
        PORT_MAP.put(23,    new String[]{"Telnet",        "Unencrypted remote access — highly dangerous",      "CRITICAL"});
        PORT_MAP.put(69,    new String[]{"TFTP",          "Trivial FTP — zero authentication required",        "CRITICAL"});
        PORT_MAP.put(512,   new String[]{"rexec",         "Remote execution — no encryption, legacy risk",     "CRITICAL"});
        PORT_MAP.put(513,   new String[]{"rlogin",        "Remote login — easily spoofed, no password",        "CRITICAL"});
        PORT_MAP.put(514,   new String[]{"rsh",           "Remote shell — unauthenticated command execution",  "CRITICAL"});
        PORT_MAP.put(2222,  new String[]{"SSH-Alt",       "Alternate SSH port — used to hide SSH service",     "HIGH"});
        PORT_MAP.put(3389,  new String[]{"RDP",           "Remote Desktop — ransomware & brute-force target",  "CRITICAL"});
        PORT_MAP.put(5800,  new String[]{"VNC-HTTP",      "VNC over HTTP — browser-based remote access",       "HIGH"});
        PORT_MAP.put(5900,  new String[]{"VNC",           "Remote desktop — weak auth, screen capture risk",   "HIGH"});
        // Mail
        PORT_MAP.put(25,    new String[]{"SMTP",          "Mail server — open relay & spam risk",              "MEDIUM"});
        PORT_MAP.put(110,   new String[]{"POP3",          "Mail retrieval — plain text passwords",             "HIGH"});
        PORT_MAP.put(143,   new String[]{"IMAP",          "Mail access — plain text if no TLS",                "MEDIUM"});
        PORT_MAP.put(465,   new String[]{"SMTPS",         "Secure mail — check for certificate issues",        "LOW"});
        PORT_MAP.put(587,   new String[]{"SMTP-Submit",   "Mail submission — open relay misconfiguration",     "MEDIUM"});
        // Web
        PORT_MAP.put(80,    new String[]{"HTTP",          "Unencrypted web server — data sniffing risk",       "LOW"});
        PORT_MAP.put(443,   new String[]{"HTTPS",         "Encrypted web server",                              "LOW"});
        PORT_MAP.put(8080,  new String[]{"HTTP-Alt",      "Dev/proxy server — check for admin panels",         "MEDIUM"});
        PORT_MAP.put(8443,  new String[]{"HTTPS-Alt",     "Alternate HTTPS — verify certificate validity",     "LOW"});
        PORT_MAP.put(8888,  new String[]{"Jupyter",       "Jupyter Notebook — remote code execution risk",     "CRITICAL"});
        PORT_MAP.put(9090,  new String[]{"Prometheus",    "Metrics server — internal data exposed publicly",   "MEDIUM"});
        PORT_MAP.put(9200,  new String[]{"Elasticsearch", "Search DB — data leak without authentication",      "CRITICAL"});
        PORT_MAP.put(9300,  new String[]{"ES-Cluster",    "Elasticsearch cluster — remote code exec risk",     "CRITICAL"});
        // Network
        PORT_MAP.put(53,    new String[]{"DNS",           "DNS resolver — amplification DDoS attack risk",     "MEDIUM"});
        PORT_MAP.put(161,   new String[]{"SNMP",          "Network monitor — community string info leak",      "HIGH"});
        PORT_MAP.put(162,   new String[]{"SNMP-Trap",     "SNMP trap receiver — network config exposed",       "HIGH"});
        PORT_MAP.put(389,   new String[]{"LDAP",          "Directory service — credential harvesting risk",    "HIGH"});
        PORT_MAP.put(636,   new String[]{"LDAPS",         "Secure LDAP — check for anonymous bind allowed",    "MEDIUM"});
        // Windows
        PORT_MAP.put(135,   new String[]{"MS-RPC",        "Windows RPC — worm & lateral movement vector",      "HIGH"});
        PORT_MAP.put(137,   new String[]{"NetBIOS-NS",    "NetBIOS name service — network recon exposure",     "HIGH"});
        PORT_MAP.put(139,   new String[]{"NetBIOS",       "NetBIOS session — EternalBlue exploit vector",      "CRITICAL"});
        PORT_MAP.put(445,   new String[]{"SMB",           "File sharing — WannaCry ransomware vector",         "CRITICAL"});
        // Databases
        PORT_MAP.put(1433,  new String[]{"MSSQL",         "Microsoft SQL Server — data breach risk",           "CRITICAL"});
        PORT_MAP.put(1521,  new String[]{"Oracle DB",     "Oracle database — unauthenticated access risk",     "CRITICAL"});
        PORT_MAP.put(3306,  new String[]{"MySQL",         "MySQL DB exposed to network — data breach risk",    "CRITICAL"});
        PORT_MAP.put(5432,  new String[]{"PostgreSQL",    "PostgreSQL DB — check remote access settings",      "HIGH"});
        PORT_MAP.put(5984,  new String[]{"CouchDB",       "CouchDB — HTTP API exposes all databases",          "CRITICAL"});
        PORT_MAP.put(6379,  new String[]{"Redis",         "Redis DB — often no auth, full data access",        "CRITICAL"});
        PORT_MAP.put(27017, new String[]{"MongoDB",       "MongoDB — unauthenticated access risk",             "CRITICAL"});
        // Other dangerous
        PORT_MAP.put(2049,  new String[]{"NFS",             "Network File System — file access without auth",      "CRITICAL"});
        PORT_MAP.put(4444,  new String[]{"Metasploit",      "Default Metasploit listener — active attack tool",    "CRITICAL"});
        PORT_MAP.put(5555,  new String[]{"ADB",             "Android Debug Bridge — full device control risk",     "CRITICAL"});
        PORT_MAP.put(6667,  new String[]{"IRC",             "IRC server — C2 botnet communication channel",        "HIGH"});
        PORT_MAP.put(7070,  new String[]{"RealServer",      "Streaming server — information disclosure risk",      "MEDIUM"});
        PORT_MAP.put(8009,  new String[]{"AJP",             "Apache JServ — Ghostcat vulnerability risk",          "CRITICAL"});
        PORT_MAP.put(11211, new String[]{"Memcached",       "Cache server — amplification attack & data leak",     "CRITICAL"});

        // Windows System & RPC Ports
        PORT_MAP.put(88,    new String[]{"Kerberos",        "Auth service — ticket-based attack target",           "HIGH"});
        PORT_MAP.put(111,   new String[]{"RPC-Bind",        "RPC portmapper — service enumeration risk",           "HIGH"});
        PORT_MAP.put(264,   new String[]{"BGMP",            "Border Gateway Multicast Protocol",                   "LOW"});
        PORT_MAP.put(593,   new String[]{"HTTP-RPC",        "Windows HTTP RPC endpoint mapper",                    "MEDIUM"});
        PORT_MAP.put(1025,  new String[]{"MS-RPC-Alt",      "Windows RPC alternate port",                          "MEDIUM"});
        PORT_MAP.put(1026,  new String[]{"Windows-MSG",     "Windows messenger service port",                      "MEDIUM"});
        PORT_MAP.put(1027,  new String[]{"Windows-RPC",     "Windows dynamic RPC port",                            "MEDIUM"});
        PORT_MAP.put(1028,  new String[]{"Windows-RPC",     "Windows dynamic RPC port",                            "MEDIUM"});
        PORT_MAP.put(1029,  new String[]{"Windows-RPC",     "Windows dynamic RPC port",                            "MEDIUM"});
        PORT_MAP.put(1030,  new String[]{"Windows-RPC",     "Windows dynamic RPC port",                            "MEDIUM"});

        // Developer & Application Ports
        PORT_MAP.put(3000,  new String[]{"Node.js/React",   "Dev server exposed — React/Node.js application",      "MEDIUM"});
        PORT_MAP.put(3001,  new String[]{"Dev-Server",      "Development server — should not be public",           "MEDIUM"});
        PORT_MAP.put(4000,  new String[]{"Dev-App",         "Custom application port — investigate",               "MEDIUM"});
        PORT_MAP.put(4200,  new String[]{"Angular",         "Angular dev server — should not be public",           "MEDIUM"});
        PORT_MAP.put(5000,  new String[]{"Flask/Python",    "Python Flask server — dev app exposed",               "MEDIUM"});
        PORT_MAP.put(5001,  new String[]{"Dev-App",         "Dev application port — investigate",                  "MEDIUM"});
        PORT_MAP.put(5173,  new String[]{"Vite",            "Vite dev server — frontend app exposed",              "MEDIUM"});
        PORT_MAP.put(7000,  new String[]{"Cassandra",       "Apache Cassandra DB inter-node communication",        "HIGH"});
        PORT_MAP.put(7001,  new String[]{"WebLogic",        "Oracle WebLogic server — RCE vulnerabilities known",  "CRITICAL"});
        PORT_MAP.put(7002,  new String[]{"WebLogic-SSL",    "Oracle WebLogic SSL — check for CVE exploits",        "HIGH"});
        PORT_MAP.put(8000,  new String[]{"HTTP-Dev",        "Dev web server — Django/Python commonly exposed",     "MEDIUM"});
        PORT_MAP.put(8161,  new String[]{"ActiveMQ",        "Apache ActiveMQ admin — default creds risk",          "CRITICAL"});
        PORT_MAP.put(8500,  new String[]{"Consul",          "HashiCorp Consul — service mesh config exposed",      "HIGH"});
        PORT_MAP.put(8983,  new String[]{"Solr",            "Apache Solr admin — RCE via Log4Shell risk",          "CRITICAL"});
        PORT_MAP.put(9000,  new String[]{"SonarQube",       "Code analysis server — source code exposure",         "HIGH"});
        PORT_MAP.put(9042,  new String[]{"Cassandra-CQL",   "Cassandra CQL port — database access risk",           "HIGH"});
        PORT_MAP.put(9092,  new String[]{"Kafka",           "Apache Kafka — message queue exposed",                "HIGH"});
        PORT_MAP.put(9200,  new String[]{"Elasticsearch",   "Search DB — data leak without authentication",        "CRITICAL"});
        PORT_MAP.put(15672, new String[]{"RabbitMQ",        "RabbitMQ management — default guest/guest creds",     "CRITICAL"});
        PORT_MAP.put(50000, new String[]{"SAP",             "SAP application server — enterprise data risk",       "HIGH"});

        // Windows Dynamic / Ephemeral Ports (commonly seen)
        PORT_MAP.put(7680,  new String[]{"WUDO",            "Windows Update Delivery Optimization",                "LOW"});
        PORT_MAP.put(7768,  new String[]{"Win-Service",     "Windows background service port",                     "LOW"});
        PORT_MAP.put(10243, new String[]{"WMP-HTTP",        "Windows Media Player HTTP sharing",                   "LOW"});
        PORT_MAP.put(33060, new String[]{"MySQL-X",         "MySQL X Protocol — modern MySQL interface",           "HIGH"});
        PORT_MAP.put(49152, new String[]{"Win-Ephemeral",   "Windows dynamic/private port range start",            "LOW"});
        PORT_MAP.put(49153, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49154, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49155, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49156, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49157, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49158, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49159, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49160, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49161, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49162, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49163, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49164, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49165, new String[]{"Win-Ephemeral",   "Windows dynamic RPC/DCOM service",                    "LOW"});
        PORT_MAP.put(49664, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49665, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49666, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49667, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49668, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49669, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49670, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49671, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49672, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
        PORT_MAP.put(49673, new String[]{"Win-RPC-DCOM",    "Windows RPC/DCOM — dynamic endpoint",                 "LOW"});
    }

    private static final int TIMEOUT_MS   = 200;   // fast timeout for full scan
    private static final int THREAD_POOL  = 500;   // 500 parallel threads
    private static final int TOTAL_PORTS  = 65535;

    private List<Integer> customPorts;
    private ProgressCallback progressCallback;
    private boolean fullScan = false;

    // Unit II: User-defined functional interface
    public interface ProgressCallback {
        void onProgress(int scanned, int total);
    }

    public PortScanner(String targetIP) {
        super(targetIP);
        this.customPorts = new ArrayList<>();
    }

    public void addCustomPorts(List<Integer> ports) {
        this.customPorts = ports;
    }

    public void setFullScan(boolean fullScan) {
        this.fullScan = fullScan;
    }

    public void setProgressCallback(ProgressCallback cb) {
        this.progressCallback = cb;
    }

    // Unit II: Method Overriding
    @Override
    public ScanResult scan() {
        if (fullScan) return fullPortScan();
        else          return quickScan();
    }

    // Quick scan — only predefined 45 ports + custom
    private ScanResult quickScan() {
        ScanResult result = new ScanResult(targetIP);
        int openCount = 0;
        String now = now();

        for (Map.Entry<Integer, String[]> entry : PORT_MAP.entrySet()) {
            int port      = entry.getKey();
            String[] info = entry.getValue();
            if (isPortOpen(port)) {
                openCount++;
                result.addThreat(new Threat(port, info[0], info[1], parseThreatLevel(info[2]), now));
            }
        }

        for (int port : customPorts) {
            if (!PORT_MAP.containsKey(port) && isPortOpen(port)) {
                openCount++;
                result.addThreat(new Threat(port, "Custom Port",
                    "User-defined port — open and responding", ThreatLevel.MEDIUM, now));
            }
        }

        result.setOpenPorts(openCount);
        result.setOverallRisk(ThreatAnalyzer.calculateRisk(result.getThreats()));
        return result;
    }

    // Unit III: ExecutorService — Thread Pool for full 65535 port scan
    private ScanResult fullPortScan() {
        ScanResult result    = new ScanResult(targetIP);
        String now           = now();
        AtomicInteger scanned = new AtomicInteger(0);   // Unit III: AtomicInteger — thread-safe counter
        AtomicInteger openCount = new AtomicInteger(0);

        // Thread-safe list for results — Unit V: ConcurrentLinkedQueue
        ConcurrentLinkedQueue<Threat> threats = new ConcurrentLinkedQueue<>();

        // Unit III: ExecutorService — fixed thread pool
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL);
        List<Future<?>> futures  = new ArrayList<>();

        for (int port = 1; port <= TOTAL_PORTS; port++) {
            final int p = port;
            // Submit each port scan as a separate task
            Future<?> future = executor.submit(() -> {
                if (isPortOpen(p)) {
                    openCount.incrementAndGet();
                    String service, desc, level;
                    if (PORT_MAP.containsKey(p)) {
                        String[] info = PORT_MAP.get(p);
                        service = info[0];
                        desc    = info[1];
                        level   = info[2];
                    } else {
                        // Try IANA real-time lookup
                        String[] iana = IANAPortLoader.lookup(p);
                        if (iana != null) {
                            service = iana[0];
                            desc    = iana[1];
                            level   = "LOW";
                        } else {
                            service = "Unregistered Port";
                            desc    = "Port " + p + " — not in IANA registry, dynamic use";
                            level   = "LOW";
                        }
                    }
                    threats.add(new Threat(p, service, desc, parseThreatLevel(level), now));
                }

                int done = scanned.incrementAndGet();
                // Report progress every 500 ports
                if (done % 500 == 0 && progressCallback != null) {
                    progressCallback.onProgress(done, TOTAL_PORTS);
                }
            });
            futures.add(future);
        }

        // Wait for all tasks to complete
        for (Future<?> f : futures) {
            try { f.get(); }
            catch (Exception e) { /* skip failed */ }
        }

        executor.shutdown();

        // Sort threats by port number — Unit V: Collections.sort
        List<Threat> sortedThreats = new ArrayList<>(threats);
        sortedThreats.sort((a, b) -> a.getPort() - b.getPort());
        for (Threat t : sortedThreats) result.addThreat(t);

        result.setOpenPorts(openCount.get());
        result.setOverallRisk(ThreatAnalyzer.calculateRisk(result.getThreats()));
        return result;
    }

    private boolean isPortOpen(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(targetIP, port), TIMEOUT_MS);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private ThreatLevel parseThreatLevel(String s) {
        switch (s) {
            case "CRITICAL": return ThreatLevel.CRITICAL;
            case "HIGH":     return ThreatLevel.HIGH;
            case "MEDIUM":   return ThreatLevel.MEDIUM;
            default:         return ThreatLevel.LOW;
        }
    }

    private String now() {
        return LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public static Map<Integer, String[]> getPortMap() {
        return PORT_MAP;
    }

    public static int getTotalPorts() {
        return TOTAL_PORTS;
    }
}
// This won't work as append - need to add to static block
