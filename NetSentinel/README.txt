╔══════════════════════════════════════════════════════════╗
   NETSENTINEL — Live Network Intrusion Detection System
╚══════════════════════════════════════════════════════════╝

DESCRIPTION:
  NetSentinel is a Java-based cybersecurity tool that scans
  any IP address or hostname for open ports, classifies
  detected services as threats (LOW / MEDIUM / HIGH / CRITICAL),
  and generates a full threat report.

HOW TO RUN (Windows):
  Double-click run.bat  OR  run from terminal:

    cd NetSentinel\src
    javac model\ThreatLevel.java model\Threat.java model\ScanResult.java ^
          engine\Scanner.java engine\ThreatAnalyzer.java engine\PortScanner.java ^
          log\AlertLogger.java log\LogManager.java ^
          thread\ScanWorker.java ui\ResultPanel.java ui\MainWindow.java
    java -cp . ui.MainWindow

HOW TO RUN (PowerShell):
  cd NetSentinel\src
  javac (Get-ChildItem -Recurse -Filter *.java | Select-Object -ExpandProperty FullName)
  java -cp . ui.MainWindow

FEATURES:
  - Scan any IP or hostname for 19 known dangerous ports
  - Real-time threat classification (CRITICAL / HIGH / MEDIUM / LOW)
  - Background scanning using Java Threads
  - Save reports to netsentinel_log.txt
  - View past scan logs inside the app
  - Dark terminal-style Swing GUI

OOP CONCEPTS COVERED:
  Unit I  - Variables, Arrays, Strings, Operators
  Unit II - Abstract class, Inheritance, Interfaces,
            Method Overloading, Method Overriding,
            static keyword, Packages, Constructors
  Unit III- Multithreading (Runnable), Exception Handling,
            FileWriter, FileReader, BufferedReader
  Unit IV - Swing GUI, Layout Managers, Event Listeners,
            Lambdas, Functional Interfaces, JDialog
  Unit V  - Collections: List, ArrayList, Map, LinkedHashMap

PROJECT STRUCTURE:
  src/
  ├── model/
  │   ├── ThreatLevel.java     (Enum)
  │   ├── Threat.java          (Data class)
  │   └── ScanResult.java      (Result with List<Threat>)
  ├── engine/
  │   ├── Scanner.java         (Abstract base class)
  │   ├── PortScanner.java     (Extends Scanner, real scanning)
  │   └── ThreatAnalyzer.java  (Static risk calculator)
  ├── thread/
  │   └── ScanWorker.java      (Implements Runnable)
  ├── log/
  │   ├── AlertLogger.java     (FileWriter logging)
  │   └── LogManager.java      (FileReader log viewer)
  └── ui/
      ├── ResultPanel.java     (Custom JPanel)
      └── MainWindow.java      (Main JFrame + entry point)
