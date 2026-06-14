package engine;

import model.Threat;
import model.ThreatLevel;

import java.util.List;

// Unit II: static keyword, method overloading
public class ThreatAnalyzer {

    // Unit II: static method
    public static String calculateRisk(List<Threat> threats) {
        if (threats.isEmpty()) return "CLEAN — No threats detected";

        long critical = threats.stream().filter(t -> t.getLevel() == ThreatLevel.CRITICAL).count();
        long high     = threats.stream().filter(t -> t.getLevel() == ThreatLevel.HIGH).count();
        long medium   = threats.stream().filter(t -> t.getLevel() == ThreatLevel.MEDIUM).count();

        if (critical > 0) return "CRITICAL RISK — Immediate action required!";
        if (high > 1)     return "HIGH RISK — Several dangerous ports open";
        if (high == 1)    return "HIGH RISK — Dangerous port detected";
        if (medium > 0)   return "MEDIUM RISK — Suspicious activity found";
        return "LOW RISK — Minor exposure detected";
    }

    // Unit II: Method Overloading — same name, different parameters
    public static String calculateRisk(int openPorts) {
        if (openPorts == 0) return "CLEAN";
        if (openPorts <= 2) return "LOW";
        if (openPorts <= 5) return "MEDIUM";
        if (openPorts <= 8) return "HIGH";
        return "CRITICAL";
    }

    public static String getThreatColor(ThreatLevel level) {
        switch (level) {
            case CRITICAL: return "#FF4444";
            case HIGH:     return "#FF8800";
            case MEDIUM:   return "#FFCC00";
            default:       return "#44FF88";
        }
    }
}
