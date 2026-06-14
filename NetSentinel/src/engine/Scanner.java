package engine;

import model.ScanResult;

// Unit II: Abstract class — base for all scanners
public abstract class Scanner {

    protected String targetIP;

    public Scanner(String targetIP) {
        this.targetIP = targetIP;
    }

    // Abstract method — must be implemented by subclasses
    public abstract ScanResult scan();

    // Concrete helper available to all subclasses
    protected boolean isValidIP(String ip) {
        String regex = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                     + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        return ip.matches(regex) || ip.equalsIgnoreCase("localhost");
    }
}
