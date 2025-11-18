/**
 * Sample code to test Checkmarx/Vorpal security scanning capabilities (C#)
 * This file contains various security vulnerabilities and bad practices
 */

using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

public class UnsafeCSharpServer : ControllerBase
{
    // ============================
    // 1. HARDCODED CREDENTIALS
    // ============================
    private const string DB_HOST = "localhost";
    private const string DB_USER = "admin"; // BAD: Hardcoded username
    private const string DB_PASSWORD = "SuperSecretPassword123!"; // BAD: Hardcoded password
    private const string DB_NAME = "myapp_db";
    
    private const string API_KEY = "sk_live_51234567890abcdefghijk"; // BAD: Hardcoded API key
    private const string SECRET_TOKEN = "my-super-secret-key-123"; // BAD: Hardcoded secret
    private const string JWT_SECRET = "super_secret_jwt_key_12345"; // BAD: Hardcoded JWT secret
    private const string ENCRYPTION_KEY = "1234567890123456"; // BAD: Hardcoded encryption key

    // ===========================
    // 2. WEAK CRYPTOGRAPHY - MD5
    // ===========================
    public static string HashPasswordMD5(string password)
    {
        try
        {
            // BAD: MD5 is cryptographically broken
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    // ===========================
    // 3. WEAK CRYPTOGRAPHY - SHA1
    // ===========================
    public static string HashPasswordSHA1(string password)
    {
        // BAD: SHA1 is deprecated and weak
        using (SHA1 sha1 = SHA1.Create())
        {
            byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
            StringBuilder sb = new StringBuilder();
            foreach (byte b in hash)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }

    // ===========================
    // 4. WEAK ENCRYPTION - XOR
    // ===========================
    public static string EncryptDataXOR(string data, string key)
    {
        // BAD: XOR is not real encryption
        StringBuilder encrypted = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            encrypted.Append((char)(data[i] ^ key[i % key.Length]));
        }
        return encrypted.ToString();
    }

    // ===========================
    // 5. WEAK ENCRYPTION - ECB Mode
    // ===========================
    public static string EncryptWithECB(string data, string key)
    {
        try
        {
            // BAD: ECB mode is insecure - identical plaintext blocks produce identical ciphertext
            byte[] keyBytes = Encoding.UTF8.GetBytes(key.PadRight(16).Substring(0, 16));
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB; // BAD: ECB mode is insecure
                aes.Key = keyBytes;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] encrypted = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
                return Convert.ToBase64String(encrypted);
            }
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    // ===========================
    // 6. SQL INJECTION VULNERABILITY
    // ===========================
    public void VulnerableSqlQuery(string userId)
    {
        try
        {
            // BAD: Direct string concatenation in SQL query
            string query = $"SELECT * FROM users WHERE id = {userId}";
            
            // This allows SQL injection like: userId = "1 OR 1=1"
            using (SqlConnection conn = new SqlConnection($"Server={DB_HOST};Database={DB_NAME};User Id={DB_USER};Password={DB_PASSWORD};"))
            {
                conn.Open();
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    SqlDataReader reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        Console.WriteLine(reader["name"]);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    // ===========================
    // 7. COMMAND INJECTION VULNERABILITY
    // ===========================
    public void VulnerableCommandExecution(string filename)
    {
        try
        {
            // BAD: Direct user input in command
            string command = $"type {filename}";
            
            // This allows command injection
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", $"/c {command}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            
            using (Process process = Process.Start(psi))
            {
                string output = process.StandardOutput.ReadToEnd();
                Console.WriteLine(output);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    // ===========================
    // 8. PATH TRAVERSAL VULNERABILITY
    // ===========================
    public string VulnerableFileRead(string filePath)
    {
        try
        {
            // BAD: No validation of file path
            return File.ReadAllText(filePath);
            
            // This allows path traversal like: filePath = "../../../../etc/passwd"
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    // ===========================
    // 9. UNSAFE DESERIALIZATION
    // ===========================
    public object UnsafeDeserialization(byte[] data)
    {
        try
        {
            // BAD: Using BinaryFormatter on untrusted data (deprecated and unsafe)
            BinaryFormatter formatter = new BinaryFormatter();
            MemoryStream ms = new MemoryStream(data);
            object obj = formatter.Deserialize(ms); // Vulnerable to gadget chain attacks
            return obj;
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            return null;
        }
    }

    // ===========================
    // 10. INSECURE XML DESERIALIZATION
    // ===========================
    public object UnsafeXmlDeserialization(string xml)
    {
        try
        {
            // BAD: Using XmlSerializer on untrusted data without DTD protection
            XmlSerializer serializer = new XmlSerializer(typeof(object));
            using (StringReader reader = new StringReader(xml))
            {
                return serializer.Deserialize(reader); // Vulnerable to XXE attacks
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            return null;
        }
    }

    // ===========================
    // 11. BROKEN AUTHENTICATION
    // ===========================
    private static Dictionary<string, string> users = new Dictionary<string, string>
    {
        // BAD: Storing passwords in plain text
        { "admin", "password123" },
        { "user", "mypassword" }
    };

    public string VulnerableLogin(string username, string password)
    {
        // BAD: Direct password comparison
        if (users.ContainsKey(username) && users[username] == password)
        {
            // BAD: Session token is too simple
            return $"{username}_token_{DateTime.Now.Ticks}";
        }
        return null;
    }

    // ===========================
    // 12. WEAK RANDOM TOKEN GENERATION
    // ===========================
    public string GenerateWeakToken()
    {
        // BAD: Using Random (not cryptographically secure)
        Random random = new Random();
        return "token_" + random.Next();
    }

    public string GenerateWeakSessionId()
    {
        // BAD: Using timestamp as session ID
        return "session_" + DateTime.Now.Ticks;
    }

    // ===========================
    // 13. MISSING AUTHENTICATION
    // ===========================
    [HttpGet("admin-data")]
    public IActionResult GetAdminData()
    {
        // BAD: No authentication check on sensitive endpoint
        var adminData = new
        {
            users = "all_users_data",
            secrets = "sensitive_info"
        };
        
        return Ok(adminData);
    }

    // ===========================
    // 14. INSECURE DIRECT OBJECT REFERENCES (IDOR)
    // ===========================
    [HttpGet("user/{userId}")]
    public IActionResult GetUserData(int userId)
    {
        // BAD: No authorization check - user can access any other user's data
        string query = $"SELECT * FROM users WHERE id = {userId}";
        
        try
        {
            using (SqlConnection conn = new SqlConnection($"Server={DB_HOST};Database={DB_NAME};User Id={DB_USER};Password={DB_PASSWORD};"))
            {
                conn.Open();
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    SqlDataAdapter adapter = new SqlDataAdapter(cmd);
                    DataTable dt = new DataTable();
                    adapter.Fill(dt);
                    return Ok(dt);
                }
            }
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    // ===========================
    // 15. UNVALIDATED REDIRECTS
    // ===========================
    [HttpGet("redirect")]
    public IActionResult UnvalidatedRedirect(string url)
    {
        // BAD: No validation of redirect URL
        return Redirect(url);
        
        // This allows open redirect
    }

    // ===========================
    // 16. XSS VULNERABILITY
    // ===========================
    [HttpGet("comment")]
    public IActionResult GetCommentPage(string comment)
    {
        // BAD: Directly rendering user input without escaping
        string html = $@"
            <html>
                <body>
                    <h1>Comment:</h1>
                    <p>{comment}</p>
                </body>
            </html>";
        
        return Content(html, "text/html");
        
        // This allows XSS like: comment=<script>alert('XSS')</script>
    }

    // ===========================
    // 17. SENSITIVE DATA EXPOSURE
    // ===========================
    public class UserData
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string SSN { get; set; } // BAD: Should not be exposed
        public string CreditCard { get; set; } // BAD: Should not be exposed
        public string PasswordHash { get; set; } // BAD: Should not be exposed
        public string ApiToken { get; set; } // BAD: Should not be exposed
    }

    public UserData GetUserDataUnsafe(int userId)
    {
        // BAD: Returning all sensitive data
        return new UserData
        {
            Id = userId,
            Name = "John Doe",
            Email = "john@example.com",
            SSN = "123-45-6789",
            CreditCard = "1234-5678-9012-3456",
            PasswordHash = "hash_value",
            ApiToken = "sk_live_abcdefgh123456"
        };
    }

    // ===========================
    // 18. MISSING ERROR HANDLING
    // ===========================
    [HttpPost("parse-data")]
    public IActionResult ParseDataUnsafely([FromBody] dynamic data)
    {
        // BAD: No try-catch or error handling
        string result = data.field.nested.value; // Potential null reference exception
        return Ok(result);
    }

    // ===========================
    // 19. INSECURE LOGGING
    // ===========================
    public void InsecureLogging(string username, string password)
    {
        // BAD: Logging sensitive data
        Console.WriteLine($"User {username} attempted login with password {password}");
    }

    // ===========================
    // 20. RACE CONDITION
    // ===========================
    public void VulnerableMoneyTransfer(int userId, decimal amount)
    {
        try
        {
            using (SqlConnection conn = new SqlConnection($"Server={DB_HOST};Database={DB_NAME};User Id={DB_USER};Password={DB_PASSWORD};"))
            {
                conn.Open();
                
                // BAD: Check-then-act without proper locking
                string selectQuery = $"SELECT balance FROM accounts WHERE id = {userId}";
                using (SqlCommand cmd = new SqlCommand(selectQuery, conn))
                {
                    decimal balance = (decimal)cmd.ExecuteScalar();
                    
                    if (balance >= amount)
                    {
                        // Time window for race condition exists here
                        string updateQuery = $"UPDATE accounts SET balance = balance - {amount} WHERE id = {userId}";
                        using (SqlCommand updateCmd = new SqlCommand(updateQuery, conn))
                        {
                            updateCmd.ExecuteNonQuery();
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    // ===========================
    // 21. INSECURE HTTP SERVER BINDING
    // ===========================
    public void StartInsecureServer()
    {
        // BAD: Binding to 0.0.0.0 makes server accessible from any network interface
        var httpListener = new HttpListener();
        httpListener.Prefixes.Add("http://0.0.0.0:8080/");
        
        // BAD: No HTTPS/TLS configuration
        // BAD: No authentication or rate limiting
        httpListener.Start();
        Console.WriteLine("Server started on 0.0.0.0:8080");
    }

    // ===========================
    // 22. MISSING AUTHENTICATION ON SENSITIVE ENDPOINTS
    // ===========================
    [HttpGet("sensitive-config")]
    public IActionResult GetSensitiveConfig()
    {
        // BAD: No authentication required
        var config = new
        {
            database_password = DB_PASSWORD,
            api_key = API_KEY,
            jwt_secret = JWT_SECRET
        };
        
        return Ok(config);
    }

    // ===========================
    // 23. INSUFFICIENT INPUT VALIDATION
    // ===========================
    public void ProcessUserInput(string input)
    {
        // BAD: No validation of input
        string query = $"INSERT INTO logs VALUES ('{input}')";
        Console.WriteLine($"Executing: {query}");
    }

    // ===========================
    // 24. USING DEPRECATED METHODS
    // ===========================
    [Obsolete]
    public string OldHashMethod(string password)
    {
        // BAD: Using obsolete methods
        return new Random().Next().ToString();
    }

    // ===========================
    // 25. INFORMATION DISCLOSURE
    // ===========================
    [HttpGet("error")]
    public IActionResult HandleError()
    {
        try
        {
            // Some operation that fails
            int result = 1 / 0;
        }
        catch (Exception ex)
        {
            // BAD: Exposing full exception details to user
            return StatusCode(500, new
            {
                error = ex.ToString(),
                stackTrace = ex.StackTrace,
                source = ex.Source
            });
        }
        return Ok();
    }

    // ===========================
    // 26. UNSAFE FILE UPLOAD
    // ===========================
    [HttpPost("upload")]
    public IActionResult UploadFile(IFormFile file)
    {
        try
        {
            // BAD: No validation of filename or content type
            string filename = file.FileName;
            string uploadPath = Path.Combine("uploads", filename);
            
            using (var fileStream = new FileStream(uploadPath, FileMode.Create))
            {
                file.CopyTo(fileStream);
            }
            
            // BAD: Executing uploaded file
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", $"/c {uploadPath}")
            {
                UseShellExecute = false
            };
            Process.Start(psi);
            
            return Ok(new { message = "File uploaded and executed" });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    // ===========================
    // 27. INSECURE RANDOM PASSWORD GENERATION
    // ===========================
    public string GenerateWeakPassword()
    {
        // BAD: Using Random instead of cryptographically secure methods
        Random random = new Random();
        string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder();
        
        for (int i = 0; i < 8; i++)
        {
            password.Append(chars[random.Next(chars.Length)]);
        }
        
        return password.ToString();
    }

    // ===========================
    // 28. INSECURE DATABASE CONNECTION
    // ===========================
    public SqlConnection GetInsecureDBConnection()
    {
        // BAD: Hardcoded credentials in connection string
        string connectionString = $"Server={DB_HOST};Database={DB_NAME};User Id={DB_USER};Password={DB_PASSWORD};Encrypt=false;TrustServerCertificate=true;";
        return new SqlConnection(connectionString);
    }

    // ===========================
    // 29. MISSING TIMEOUT CONFIGURATION
    // ===========================
    public void ConnectWithoutTimeout(string host, int port)
    {
        try
        {
            // BAD: No timeout set
            TcpClient client = new TcpClient();
            client.Connect(host, port); // Can hang indefinitely
            
            NetworkStream stream = client.GetStream();
            // BAD: Server can hang indefinitely without timeout
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    // ===========================
    // 30. RESOURCE LEAK
    // ===========================
    public string ReadFileWithResourceLeak(string filename)
    {
        try
        {
            // BAD: Resource not properly closed in case of exception
            StreamReader reader = new StreamReader(filename);
            string line = reader.ReadLine();
            // If exception occurs here, resource won't be closed
            reader.Close();
            return line;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    // ===========================
    // 31. INSECURE HTTP CLIENT
    // ===========================
    public async System.Threading.Tasks.Task FetchDataInsecurely()
    {
        // BAD: Allowing insecure SSL/TLS certificates
        HttpClientHandler handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true; // Accept all certificates
        
        using (HttpClient client = new HttpClient(handler))
        {
            // BAD: Sending credentials in plain HTTP
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {API_KEY}");
            var response = await client.GetAsync("http://example.com/api/data");
        }
    }

    // ===========================
    // 32. INSECURE COOKIES
    // ===========================
    [HttpPost("login-insecure")]
    public IActionResult LoginInsecure(string username, string password)
    {
        if (VulnerableLogin(username, password) != null)
        {
            // BAD: Creating insecure cookies
            var cookieOptions = new CookieOptions
            {
                Secure = false, // BAD: Should be true for HTTPS only
                HttpOnly = false, // BAD: Should be true to prevent JavaScript access
                SameSite = SameSiteMode.None // BAD: Should be Strict or Lax
            };
            
            Response.Cookies.Append("auth_token", "token_value", cookieOptions);
            return Ok(new { message = "Logged in" });
        }
        
        return Unauthorized();
    }
}

// ===========================
// ADDITIONAL USAGE EXAMPLE
// ===========================
public class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Starting unsafe C# server...");
        
        var server = new UnsafeCSharpServer();
        // BAD: Starting insecure server
        server.StartInsecureServer();
    }
}
