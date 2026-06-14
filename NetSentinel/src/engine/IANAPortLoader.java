package engine;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

// Unit III: HttpURLConnection, BufferedReader, IOException
// Unit V:  Collections — HashMap for port lookup
// Unit II: static methods, encapsulation
public class IANAPortLoader {

    private static final String IANA_URL =
        "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv";

    // Unit V: HashMap — port number to service name
    private static final Map<Integer, String> IANA_MAP = new HashMap<>();
    private static boolean loaded = false;
    private static String  loadStatus = "Not loaded";

    // Unit II: static method — called once at startup
    public static void load() {
        if (loaded) return;
        try {
            loadFromIANA();
            loadStatus = "IANA loaded — " + IANA_MAP.size() + " ports mapped";
            loaded = true;
        } catch (Exception e) {
            loadStatus = "IANA offline — using local map only";
            loaded = false;
        }
    }

    // Unit III: try-with-resources, BufferedReader, IOException handling
    private static void loadFromIANA() throws Exception {
        URL url = new URL(IANA_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(8000);
        conn.setRequestProperty("User-Agent", "NetSentinel/2.0");

        if (conn.getResponseCode() != 200)
            throw new Exception("IANA returned: " + conn.getResponseCode());

        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {

            String line;
            boolean firstLine = true;

            while ((line = br.readLine()) != null) {
                // Skip header line
                if (firstLine) { firstLine = false; continue; }

                // CSV format: ServiceName,PortNumber,TransportProtocol,Description,...
                String[] cols = line.split(",", -1);
                if (cols.length < 4) continue;

                String serviceName = cols[0].trim();
                String portStr     = cols[1].trim();
                String protocol    = cols[2].trim().toLowerCase();
                String description = cols[3].trim();

                // Only TCP ports, skip blank names/ports
                if (serviceName.isEmpty() || portStr.isEmpty()) continue;
                if (!protocol.equals("tcp")) continue;

                // Skip port ranges like "1024-65535"
                if (portStr.contains("-")) continue;

                try {
                    int port = Integer.parseInt(portStr);
                    if (port > 0 && port <= 65535) {
                        // Clean up description
                        if (description.isEmpty()) description = serviceName + " service";
                        // Truncate long descriptions
                        if (description.length() > 60)
                            description = description.substring(0, 57) + "...";
                        IANA_MAP.put(port, serviceName + "|" + description);
                    }
                } catch (NumberFormatException ignored) {}
            }
        }
    }

    // Lookup a port — returns array [serviceName, description] or null
    public static String[] lookup(int port) {
        String entry = IANA_MAP.get(port);
        if (entry == null) return null;
        String[] parts = entry.split("\\|", 2);
        if (parts.length == 2) return parts;
        return new String[]{parts[0], parts[0] + " service"};
    }

    public static boolean isLoaded()      { return loaded; }
    public static String  getLoadStatus() { return loadStatus; }
    public static int     getPortCount()  { return IANA_MAP.size(); }
}
