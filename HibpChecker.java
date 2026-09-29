import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.io.InputStream;

public class HibpChecker {

    private static final String API_URL = "https://api.pwnedpasswords.com/range/";
    private static final String USER_AGENT = "Java-Password-Strength-Detector";

    //Only first 5 letters of SHA-1 Hash are used
    public static int checkPassword(String password) throws Exception {
        // hash the password
        String sha1Hash = sha1Hex(password).toUpperCase();

        // split into first 5 characters and then the rest in suffix
        String prefix = sha1Hash.substring(0, 5);
        String suffix = sha1Hash.substring(5);

        // Send the prefix to the API
        String response = queryApi(prefix);

        // search response with our suffix
        for (String line : response.split("\r?\n")) {
            String[] parts = line.split(":");
            if (parts.length == 2 && parts[0].equalsIgnoreCase(suffix)) {
                return Integer.parseInt(parts[1].trim());
            }
        }
        return 0;
    }
    
    //SHA-1 hash
    private static String sha1Hex(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

        //convert to hex
        String hex = "";
        for (byte b : hash) {
            int value = b & 0xFF;                     
            String pair = Integer.toHexString(value);  
            if (pair.length() == 1) {
                pair = "0" + pair;                     
            }
            hex = hex + pair;
        }
        return hex;
    }

    private static String queryApi(String prefix) throws Exception {
        //Make full URL using prefix to connect to API and request info
        URL url = new URL(API_URL + prefix);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("User-Agent", USER_AGENT);

        InputStream inputStream = conn.getInputStream();
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
        BufferedReader reader = new BufferedReader(inputStreamReader);

        //Take in info from api
        String response = "";
        String line = reader.readLine();
        while (line != null) {
            response = response + line + "\n";
            line = reader.readLine();
        }

        // Close reader and disconnect from api
        reader.close();
        conn.disconnect();

        return response;
    }
}
