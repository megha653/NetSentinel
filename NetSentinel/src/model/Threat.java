package model;

// Unit II: Class, Constructors, Encapsulation, this keyword
public class Threat {

    private int port;
    private String service;
    private String description;
    private ThreatLevel level;
    private String timestamp;

    public Threat(int port, String service, String description, ThreatLevel level, String timestamp) {
        this.port        = port;
        this.service     = service;
        this.description = description;
        this.level       = level;
        this.timestamp   = timestamp;
    }

    // Getters
    public int getPort()           { return port; }
    public String getService()     { return service; }
    public String getDescription() { return description; }
    public ThreatLevel getLevel()  { return level; }
    public String getTimestamp()   { return timestamp; }

    @Override
    public String toString() {
        return String.format("[%s] Port %-6d | %-18s | %s", level, port, service, description);
    }
}
