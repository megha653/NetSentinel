@echo off
echo Compiling NetSentinel...
cd src
javac model/ThreatLevel.java model/Threat.java model/ScanResult.java engine/Scanner.java engine/ThreatAnalyzer.java engine/PortScanner.java log/AlertLogger.java log/LogManager.java thread/ScanWorker.java ui/ResultPanel.java ui/MainWindow.java
echo Launching NetSentinel...
java -cp . ui.MainWindow
pause
