package model;

import java.util.List;
import java.util.ArrayList;

// Unit V: Collections — List, ArrayList
public class ScanResult {

    private String targetIP;
    private List<Threat> threats;
    private int openPorts;
    private String overallRisk;

    public ScanResult(String targetIP) {
        this.targetIP  = targetIP;
        this.threats   = new ArrayList<>();
        this.openPorts = 0;
    }

    public void addThreat(Threat t)    { threats.add(t); }
    public void setOpenPorts(int n)    { openPorts = n; }
    public void setOverallRisk(String r) { overallRisk = r; }

    public String getTargetIP()        { return targetIP; }
    public List<Threat> getThreats()   { return threats; }
    public int getOpenPorts()          { return openPorts; }
    public String getOverallRisk()     { return overallRisk; }
}
