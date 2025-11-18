/**
 * Sample code to test Checkmarx/Vorpal security scanning capabilities (Java)
 * This file contains various security vulnerabilities and bad practices
 */

import java.io.*;
import java.net.*;
import java.sql.*;
import java.security.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.sun.net.httpserver.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class UnsafeJavaServer {

    // ============================
    // 1. HARDCODED CREDENTIALS
    // ============================
    private static final String DB_HOST = "localhost";
    private static final String DB_USER = "admin"; // BAD: Hardcoded username
    private static final String DB_PASSWORD = "SuperSecretPassword123!"; // BAD: Hardcoded password
    private static final String DB_NAME = "myapp_db";
    
    private static final String API_KEY = "sk_live_51234567890abcdefghijk"; // BAD: Hardcoded API key
    private static final String SECRET_TOKEN = "my-super-secret-key-123"; // BAD: Hardcoded secret
    private static final String JWT_SECRET = "super_secret_jwt_key_12345"; // BAD: Hardcoded JWT secret

    // ===========================
    // 2. WEAK CRYPTOGRAPHY - MD5
    // ===========================
    public static String hashPasswordMD5(String password) {
        try {
            // BAD: MD5 is cryptographically broken
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : messageDigest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    // ===========================
    // 3. WEAK CRYPTOGRAPHY - SHA1
    // ===========================
    public static String hashPasswordSHA1(String password) {
        // BAD: SHA1 is deprecated and weak
        return DigestUtils.sha1Hex(password);
    }

    // ===========================
    // 4. WEAK ENCRYPTION - XOR
    // ===========================
    public static String encryptDataXOR(String data, String key) {
        // BAD: XOR is not real encryption
        StringBuilder encrypted = new StringBuilder();
        for (int i = 0; i < data.length(); i++) {
            encrypted.append((char) (data.charAt(i) ^ key.charAt(i % key.length())));
        }
        return encrypted.toString();
    }

    // ===========================
    // 5. WEAK ENCRYPTION - ECB Mode
    // ===========================
    public static String encryptWithECB(String data, String key) throws Exception {
        // BAD: ECB mode is insecure - identical plaintext blocks produce identical ciphertext
        byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKeySpec secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // ===========================
    // 6. SQL INJECTION VULNERABILITY
    // ===========================
    public static void vulnerableSqlQuery(String userId) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/" + DB_NAME,
                DB_USER,
                DB_PASSWORD
            );
            
            // BAD: Direct string concatenation in SQL query
            String query = "SELECT * FROM users WHERE id = " + userId;
            
            // This allows SQL injection like: userId = "1 OR 1=1"
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                System.out.println(rs.getString("name"));
            }
            
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ===========================
    // 7. COMMAND INJECTION VULNERABILITY
    // ===========================
    public static void vulnerableCommandExecution(String filename) {
        try {
            // BAD: Direct user input in command
            String command = "cat " + filename;
            
            // This allows command injection
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // ===========================
    // 8. PATH TRAVERSAL VULNERABILITY
    // ===========================
    public static String vulnerableFileRead(String filePath) {
        try {
            // BAD: No validation of file path
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();
            return content.toString();
            
            // This allows path traversal like: filePath = "../../../../etc/passwd"
        } catch (IOException e) {
            return e.getMessage();
        }
    }

    // ===========================
    // 9. UNSAFE DESERIALIZATION
    // ===========================
    public static Object unsafeDeserialization(byte[] data) {
        try {
            // BAD: Using ObjectInputStream on untrusted data
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject(); // Vulnerable to gadget chain attacks
            ois.close();
            return obj;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    // ===========================
    // 10. INSECURE REFLECTION
    // ===========================
    public static void invokeMethodUnsafely(String className, String methodName) {
        try {
            // BAD: Loading and invoking methods based on user input
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            clazz.getMethod(methodName).invoke(instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ===========================
    // 11. BROKEN AUTHENTICATION
    // ===========================
    private static final Map<String, String> USERS = new HashMap<>();
    static {
        // BAD: Storing passwords in plain text
        USERS.put("admin", "password123");
        USERS.put("user", "mypassword");
    }

    public static String vulnerableLogin(String username, String password) {
        // BAD: Direct password comparison
        if (USERS.containsKey(username) && USERS.get(username).equals(password)) {
            // BAD: Session token is too simple
            return username + "_token_" + System.currentTimeMillis();
        }
        return null;
    }

    // ===========================
    // 12. WEAK RANDOM TOKEN GENERATION
    // ===========================
    public static String generateWeakToken() {
        // BAD: Using Random (not cryptographically secure)
        Random random = new Random();
        return "token_" + random.nextLong();
    }

    public static String generateWeakSessionId() {
        // BAD: Using timestamp as session ID
        return "session_" + System.currentTimeMillis();
    }

    // ===========================
    // 13. MISSING AUTHENTICATION
    // ===========================
    public void handleAdminDataRequest(HttpExchange exchange) throws IOException {
        // BAD: No authentication check on sensitive endpoint
        String response = "{\"users\": \"all_users_data\", \"secrets\": \"sensitive_info\"}";
        
        exchange.sendResponseHeaders(200, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    // ===========================
    // 14. INSECURE DIRECT OBJECT REFERENCES (IDOR)
    // ===========================
    public static ResultSet getUserData(int userId) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/" + DB_NAME,
                DB_USER,
                DB_PASSWORD
            );
            
            // BAD: No authorization check - user can access any other user's data
            String query = "SELECT * FROM users WHERE id = " + userId;
            Statement stmt = conn.createStatement();
            return stmt.executeQuery(query);
        } catch (SQLException e) {
            e.printStackTrace();
            return null;
        }
    }

    // ===========================
    // 15. UNVALIDATED REDIRECTS
    // ===========================
    public void handleRedirectRequest(HttpExchange exchange) throws IOException {
        String redirectUrl = exchange.getRequestURI().getQuery();
        
        // BAD: No validation of redirect URL
        exchange.getResponseHeaders().set("Location", redirectUrl);
        exchange.sendResponseHeaders(302, 0);
        exchange.close();
        
        // This allows open redirect
    }

    // ===========================
    // 16. XSS VULNERABILITY
    // ===========================
    public String generateHTMLWithUserInput(String userComment) {
        // BAD: Directly embedding user input without escaping
        return "<html><body><p>" + userComment + "</p></body></html>";
    }

    // ===========================
    // 17. SENSITIVE DATA EXPOSURE
    // ===========================
    public static class UserData {
        public int id;
        public String name;
        public String email;
        public String ssn; // BAD: Should not be exposed
        public String creditCard; // BAD: Should not be exposed
        public String passwordHash; // BAD: Should not be exposed
        public String apiToken; // BAD: Should not be exposed
    }

    public UserData getUserDataUnsafe(int userId) {
        // BAD: Returning all sensitive data
        UserData user = new UserData();
        user.id = userId;
        user.name = "John Doe";
        user.email = "john@example.com";
        user.ssn = "123-45-6789";
        user.creditCard = "1234-5678-9012-3456";
        user.passwordHash = "hash_value";
        user.apiToken = "sk_live_abcdefgh123456";
        return user;
    }

    // ===========================
    // 18. MISSING ERROR HANDLING
    // ===========================
    public String parseJSONUnsafely(String json) {
        // BAD: No try-catch or error handling
        // Assuming use of JSON parser that throws exceptions
        Object data = new Object(); // Simplified for example
        return data.toString();
    }

    // ===========================
    // 19. INSECURE LOGGING
    // ===========================
    public static void insecureLogging(String username, String password) {
        // BAD: Logging sensitive data
        System.out.println("User " + username + " attempted login with password " + password);
    }

    // ===========================
    // 20. RACE CONDITION
    // ===========================
    public static void vulnerableMoneyTransfer(int userId, double amount) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/" + DB_NAME,
                DB_USER,
                DB_PASSWORD
            );
            
            // BAD: Check-then-act without proper locking
            String selectQuery = "SELECT balance FROM accounts WHERE id = " + userId;
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(selectQuery);
            
            if (rs.next() && rs.getDouble("balance") >= amount) {
                // Time window for race condition exists here
                String updateQuery = "UPDATE accounts SET balance = balance - " + amount + " WHERE id = " + userId;
                stmt.execute(updateQuery);
            }
            
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ===========================
    // 21. INSECURE HTTP SERVER BINDING
    // ===========================
    public static void startInsecureServer() throws IOException {
        // BAD: Binding to 0.0.0.0 makes server accessible from any network interface
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
        
        server.createContext("/api", exchange -> {
            String response = "Hello World";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        });
        
        // BAD: No HTTPS/TLS configuration
        // BAD: No authentication or rate limiting
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on 0.0.0.0:8080");
    }

    // ===========================
    // 22. MISSING AUTHENTICATION ON SENSITIVE ENDPOINTS
    // ===========================
    public void handleSensitiveDataEndpoint(HttpExchange exchange) throws IOException {
        // BAD: No authentication required
        String response = "{\"database_config\": \"" + DB_PASSWORD + "\"}";
        exchange.sendResponseHeaders(200, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    // ===========================
    // 23. INSUFFICIENT INPUT VALIDATION
    // ===========================
    public static void processUserInput(String input) {
        // BAD: No validation of input
        String query = "INSERT INTO logs VALUES ('" + input + "')";
        System.out.println("Executing: " + query);
    }

    // ===========================
    // 24. USING DEPRECATED METHODS
    // ===========================
    @Deprecated
    public static String oldHashMethod(String password) {
        // BAD: Using Date which is deprecated for hashing
        return String.valueOf(new Date().getTime());
    }

    // ===========================
    // 25. INFORMATION DISCLOSURE
    // ===========================
    public void handleErrorRequest(HttpExchange exchange) throws IOException {
        try {
            // Some operation that fails
            int result = 1 / 0;
        } catch (Exception e) {
            // BAD: Exposing full stack trace to user
            String response = e.toString() + "\n" + Arrays.toString(e.getStackTrace());
            exchange.sendResponseHeaders(500, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    // ===========================
    // 26. UNSAFE FILE UPLOAD
    // ===========================
    public void handleFileUpload(String filename, byte[] fileContent) throws IOException {
        // BAD: No validation of filename or content
        FileOutputStream fos = new FileOutputStream("uploads/" + filename);
        fos.write(fileContent);
        fos.close();
        
        // BAD: Executing uploaded file
        try {
            Runtime.getRuntime().exec("java -jar uploads/" + filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // ===========================
    // 27. INSECURE RANDOM PASSWORD GENERATION
    // ===========================
    public static String generateWeakPassword() {
        // BAD: Using Random instead of SecureRandom
        Random random = new Random();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }
        return password.toString();
    }

    // ===========================
    // 28. INSECURE JDBC CONNECTION
    // ===========================
    public Connection getInsecureDBConnection() throws SQLException {
        // BAD: Hardcoded credentials in connection string
        String url = "jdbc:mysql://localhost:3306/test_db?user=root&password=root123&allowPublicKeyRetrieval=true&useSSL=false";
        return DriverManager.getConnection(url);
    }

    // ===========================
    // 29. MISSING TIMEOUT CONFIGURATION
    // ===========================
    public void socketWithoutTimeout(String host, int port) throws IOException {
        // BAD: No timeout set
        Socket socket = new Socket(host, port);
        // BAD: Server can hang indefinitely
        InputStream input = socket.getInputStream();
    }

    // ===========================
    // 30. RESOURCE LEAK
    // ===========================
    public String readFileWithResourceLeak(String filename) throws IOException {
        // BAD: Resource not closed in case of exception
        FileReader reader = new FileReader(filename);
        BufferedReader bufferedReader = new BufferedReader(reader);
        String line = bufferedReader.readLine();
        // If exception occurs here, resource won't be closed
        bufferedReader.close();
        reader.close();
        return line;
    }

    public static void main(String[] args) throws IOException {
        System.out.println("Starting unsafe Java server...");
        
        // BAD: Starting insecure server bound to 0.0.0.0
        startInsecureServer();
    }
}
