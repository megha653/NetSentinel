package engine;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

// Unit III: IOException, try-with-resources
// Unit II: static methods, encapsulation
public class ReputationChecker {

    private static final String API_KEY = "3203b0c615463ab88419bb4bbc70e162aeaa87bbc5f4585dde8b43d787b06305dd83281984302597";

    public static ReputationResult check(String ip) {
        if (isPrivateIP(ip)) {
            return new ReputationResult(ip, false, 0,
                "Private/local IP — not in public threat databases.");
        }
        try {
            return checkAbuseIPDB(ip);
        } catch (Exception e) {
            return heuristicCheck(ip);
        }
    }

    // Unit III: HttpURLConnection, BufferedReader, IOException
    private static ReputationResult checkAbuseIPDB(String ip) throws Exception {
        String urlStr = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90&verbose";
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Key", API_KEY);         // ← API key sent here
        conn.setRequestProperty("Accept", "application/json");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) throw new Exception("API error: " + responseCode);

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
        }

        String json = sb.toString();

        int abuseScore   = extractInt(json, "abuseConfidenceScore");
        int totalReports = extractInt(json, "totalReports");
        String country   = extractString(json, "countryCode");
        String isp       = extractString(json, "isp");
        String domain    = extractString(json, "domain");
        boolean isTor    = json.contains("\"isTor\":true");

        boolean isMalicious = abuseScore > 20 || totalReports > 5 || isTor;

        String summary;
        if (isTor) {
            summary = "TOR EXIT NODE — anonymous traffic router! | Country: " + country;
        } else if (abuseScore > 75) {
            summary = "HIGHLY MALICIOUS — " + totalReports + " reports | ISP: " + isp + " | " + country;
        } else if (abuseScore > 20) {
            summary = "SUSPICIOUS — Score: " + abuseScore + "% | " + totalReports + " reports | " + country;
        } else if (totalReports > 0) {
            summary = "MONITORED — " + totalReports + " past reports | Domain: " + domain + " | " + country;
        } else {
            summary = "CLEAN — No abuse reports | ISP: " + isp + " | Country: " + country;
        }

        return new ReputationResult(ip, isMalicious, abuseScore, summary);
    }

    private static ReputationResult heuristicCheck(String ip) {
        String[] suspiciousRanges = {
            "185.220.", "194.165.", "45.33.",
            "198.199.", "167.99.",  "104.236."
        };
        for (String range : suspiciousRanges) {
            if (ip.startsWith(range)) {
                return new ReputationResult(ip, true, 85,
                    "SUSPICIOUS RANGE — Known source of scanning/attacks (offline check)");
            }
        }
        return new ReputationResult(ip, false, 0,
            "Unable to verify online — no internet connection. Local check: clean.");
    }

    private static int extractInt(String json, String key) {
        try {
            String search = "\"" + key + "\":";
            int idx = json.indexOf(search);
            if (idx == -1) return 0;
            int start = idx + search.length();
            int end = start;
            while (end < json.length() && Character.isDigit(json.charAt(end))) end++;
            return Integer.parseInt(json.substring(start, end));
        } catch (Exception e) { return 0; }
    }

    private static String extractString(String json, String key) {
        try {
            String search = "\"" + key + "\":\"";
            int idx = json.indexOf(search);
            if (idx == -1) return "N/A";
            int start = idx + search.length();
            int end = json.indexOf("\"", start);
            return json.substring(start, end);
        } catch (Exception e) { return "N/A"; }
    }

    private static boolean isPrivateIP(String ip) {
        return ip.equals("localhost")
            || ip.startsWith("127.")
            || ip.startsWith("192.168.")
            || ip.startsWith("10.")
            || ip.startsWith("172.");
    }

    public static class ReputationResult {
        private String ip;
        private boolean malicious;
        private int abuseScore;
        private String summary;

        public ReputationResult(String ip, boolean malicious, int abuseScore, String summary) {
            this.ip        = ip;
            this.malicious = malicious;
            this.abuseScore = abuseScore;
            this.summary   = summary;
        }

        public String getIp()        { return ip; }
        public boolean isMalicious() { return malicious; }
        public int getAbuseScore()   { return abuseScore; }
        public String getSummary()   { return summary; }
    }
}
