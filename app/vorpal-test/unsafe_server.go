/**
 * Sample code to test Checkmarx/Vorpal security scanning capabilities (Go)
 * This file contains various security vulnerabilities and bad practices
 */

package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ============================
// 1. HARDCODED CREDENTIALS
// ============================
const (
	DB_HOST       = "localhost"
	DB_USER       = "admin"                              // BAD: Hardcoded username
	DB_PASSWORD   = "SuperSecretPassword123!"            // BAD: Hardcoded password
	DB_NAME       = "myapp_db"
	API_KEY       = "sk_live_51234567890abcdefghijk"     // BAD: Hardcoded API key
	SECRET_TOKEN  = "my-super-secret-key-123"            // BAD: Hardcoded secret
	JWT_SECRET    = "super_secret_jwt_key_12345"         // BAD: Hardcoded JWT secret
	ENCRYPTION_KEY = "1234567890123456"                  // BAD: Hardcoded encryption key
)

// ===========================
// 2. WEAK CRYPTOGRAPHY - MD5
// ===========================
func hashPasswordMD5(password string) string {
	// BAD: MD5 is cryptographically broken
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// ===========================
// 3. WEAK CRYPTOGRAPHY - SHA1
// ===========================
func hashPasswordSHA1(password string) string {
	// BAD: SHA1 is deprecated and weak
	hash := sha1.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// ===========================
// 4. WEAK ENCRYPTION - XOR
// ===========================
func encryptDataXOR(data string, key string) string {
	// BAD: XOR is not real encryption
	var encrypted []byte
	for i, char := range data {
		encrypted = append(encrypted, byte(char^rune(key[i%len(key)])))
	}
	return string(encrypted)
}

// ===========================
// 5. WEAK ENCRYPTION - ECB Mode (Manual Implementation)
// ===========================
func encryptWithSimpleKey(data string, key string) string {
	// BAD: Simple XOR-based encryption is not secure
	result := ""
	for i, char := range data {
		result += string(rune(char) ^ rune(key[i%len(key)]))
	}
	return result
}

// ===========================
// 6. SQL INJECTION VULNERABILITY
// ===========================
func vulnerableSqlQuery(userID string) error {
	// BAD: Direct string concatenation in SQL query
	query := "SELECT * FROM users WHERE id = " + userID
	
	// This allows SQL injection like: userID = "1 OR 1=1"
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", DB_USER, DB_PASSWORD, DB_HOST, DB_NAME))
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		err := rows.Scan(&name)
		if err != nil {
			return err
		}
		fmt.Println(name)
	}

	return nil
}

// ===========================
// 7. COMMAND INJECTION VULNERABILITY
// ===========================
func vulnerableCommandExecution(filename string) error {
	// BAD: Direct user input in command
	command := "cat " + filename
	
	// This allows command injection
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}

// ===========================
// 8. PATH TRAVERSAL VULNERABILITY
// ===========================
func vulnerableFileRead(filePath string) (string, error) {
	// BAD: No validation of file path
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	
	// This allows path traversal like: filePath = "../../../../etc/passwd"
	return string(data), nil
}

// ===========================
// 9. UNSAFE DESERIALIZATION
// ===========================
type UserData struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	SSN      string `json:"ssn"`
	Password string `json:"password"`
}

func unsafeJSONDeserialization(jsonData string) (UserData, error) {
	// BAD: Deserializing untrusted JSON without validation
	var user UserData
	err := json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		return UserData{}, err
	}
	
	// Directly using user data without validation
	return user, nil
}

// ===========================
// 10. SQL INJECTION - FORMATTED STRINGS
// ===========================
func vulnerableSqlWithFormat(userID string, username string) error {
	// BAD: Using fmt.Sprintf to build SQL query
	query := fmt.Sprintf("INSERT INTO users (id, username) VALUES ('%s', '%s')", userID, username)
	
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", DB_USER, DB_PASSWORD, DB_HOST, DB_NAME))
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(query)
	return err
}

// ===========================
// 11. BROKEN AUTHENTICATION
// ===========================
var users = map[string]string{
	"admin": "password123", // BAD: Plain text password
	"user":  "mypassword",
}

func vulnerableLogin(username string, password string) (string, error) {
	// BAD: Direct password comparison
	if storedPassword, exists := users[username]; exists && storedPassword == password {
		// BAD: Session token is too simple
		return fmt.Sprintf("%s_token_%d", username, time.Now().Unix()), nil
	}
	return "", fmt.Errorf("invalid credentials")
}

// ===========================
// 12. WEAK RANDOM TOKEN GENERATION
// ===========================
func generateWeakToken() string {
	// BAD: Using simple timestamp as token
	return fmt.Sprintf("token_%d", time.Now().UnixNano())
}

func generateWeakSessionID() string {
	// BAD: Using timestamp as session ID
	return fmt.Sprintf("session_%d", time.Now().Unix())
}

// ===========================
// 13. MISSING AUTHENTICATION
// ===========================
func handleAdminDataRequest(w http.ResponseWriter, r *http.Request) {
	// BAD: No authentication check on sensitive endpoint
	adminData := map[string]interface{}{
		"users":   "all_users_data",
		"secrets": "sensitive_info",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(adminData)
}

// ===========================
// 14. INSECURE DIRECT OBJECT REFERENCES (IDOR)
// ===========================
func handleGetUserData(w http.ResponseWriter, r *http.Request) {
	// BAD: No authorization check - user can access any other user's data
	userID := r.URL.Query().Get("id")
	
	// BAD: Direct SQL query with user input
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
	
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", DB_USER, DB_PASSWORD, DB_HOST, DB_NAME))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

// ===========================
// 15. UNVALIDATED REDIRECTS
// ===========================
func handleUnvalidatedRedirect(w http.ResponseWriter, r *http.Request) {
	// BAD: No validation of redirect URL
	redirectURL := r.URL.Query().Get("url")
	
	// This allows open redirect
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ===========================
// 16. XSS VULNERABILITY
// ===========================
func handleXSSVulnerability(w http.ResponseWriter, r *http.Request) {
	// BAD: Directly rendering user input without escaping
	userComment := r.URL.Query().Get("comment")
	
	html := fmt.Sprintf(`
		<html>
			<body>
				<h1>Comment:</h1>
				<p>%s</p>
			</body>
		</html>
	`, userComment)
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
	
	// This allows XSS like: comment=<script>alert('XSS')</script>
}

// ===========================
// 17. SENSITIVE DATA EXPOSURE
// ===========================
func getUserDataUnsafe(userID int) UserData {
	// BAD: Returning all sensitive data
	return UserData{
		ID:       userID,
		Name:     "John Doe",
		Email:    "john@example.com",
		SSN:      "123-45-6789", // Should not be exposed
		Password: "password123",  // Should not be exposed
	}
}

// ===========================
// 18. MISSING ERROR HANDLING
// ===========================
func parseJSONUnsafely(jsonStr string) map[string]interface{} {
	// BAD: No error handling
	var data map[string]interface{}
	json.Unmarshal([]byte(jsonStr), &data)
	
	// Potential panic if data structure is different
	return data
}

// ===========================
// 19. INSECURE LOGGING
// ===========================
func insecureLogging(username string, password string) {
	// BAD: Logging sensitive data
	log.Printf("User %s attempted login with password %s", username, password)
}

// ===========================
// 20. RACE CONDITION
// ===========================
var accountBalance = map[int]float64{
	1: 1000.0,
}

func vulnerableMoneyTransfer(userID int, amount float64) error {
	// BAD: Check-then-act without proper locking
	if accountBalance[userID] >= amount {
		// Time window for race condition exists here
		accountBalance[userID] -= amount
		return nil
	}
	return fmt.Errorf("insufficient balance")
}

// ===========================
// 21. INSECURE HTTP SERVER BINDING
// ===========================
func startInsecureServer() {
	// BAD: Binding to 0.0.0.0 makes server accessible from any network interface
	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	})

	// BAD: No HTTPS/TLS configuration
	// BAD: No authentication or rate limiting
	fmt.Println("Server started on 0.0.0.0:8080")
	err := http.ListenAndServe("0.0.0.0:8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

// ===========================
// 22. MISSING AUTHENTICATION ON SENSITIVE ENDPOINTS
// ===========================
func handleSensitiveConfig(w http.ResponseWriter, r *http.Request) {
	// BAD: No authentication required
	config := map[string]string{
		"db_password": DB_PASSWORD,
		"api_key":     API_KEY,
		"jwt_secret":  JWT_SECRET,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// ===========================
// 23. INSUFFICIENT INPUT VALIDATION
// ===========================
func processUserInput(input string) error {
	// BAD: No validation of input
	query := fmt.Sprintf("INSERT INTO logs VALUES ('%s')", input)
	fmt.Println("Executing:", query)
	return nil
}

// ===========================
// 24. HARDCODED DATABASE CREDENTIALS
// ===========================
func getInsecureDBConnection() (*sql.DB, error) {
	// BAD: Hardcoded credentials in connection string
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", DB_USER, DB_PASSWORD, DB_HOST, DB_NAME)
	return sql.Open("mysql", dsn)
}

// ===========================
// 25. MISSING TIMEOUT CONFIGURATION
// ===========================
func connectWithoutTimeout(host string, port int) (net.Conn, error) {
	// BAD: No timeout set - can hang indefinitely
	address := fmt.Sprintf("%s:%d", host, port)
	return net.Dial("tcp", address)
}

// ===========================
// 26. UNSAFE FILE OPERATIONS
// ===========================
func handleFileUpload(w http.ResponseWriter, r *http.Request) error {
	// BAD: No validation of filename or file size
	file, handler, err := r.FormFile("file")
	if err != nil {
		return err
	}
	defer file.Close()

	// BAD: No filename validation - vulnerable to path traversal
	f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	io.Copy(f, file)

	// BAD: Executing uploaded file
	cmd := exec.Command(handler.Filename)
	return cmd.Run()
}

// ===========================
// 27. INFORMATION DISCLOSURE
// ===========================
func handleErrorRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			// BAD: Exposing detailed error information
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      fmt.Sprintf("%v", err),
				"stacktrace": fmt.Sprintf("%v", err),
			})
		}
	}()

	// Some operation that panics
	panic("Database connection failed")
}

// ===========================
// 28. INSECURE HTTP CLIENT
// ===========================
func fetchDataInsecurely() error {
	// BAD: Allowing insecure HTTPS (skipping certificate verification)
	tr := &http.Transport{
		InsecureSkipVerify: true, // BAD: Skips TLS verification
	}
	client := &http.Client{Transport: tr}

	// BAD: Sending sensitive data in plain HTTP
	req, _ := http.NewRequest("GET", "http://example.com/api/data", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", API_KEY))

	_, err := client.Do(req)
	return err
}

// ===========================
// 29. GLOBAL VARIABLE MUTATION
// ===========================
var globalSecret = "initial_secret" // BAD: Mutable global variable

func updateGlobalSecret(newSecret string) {
	// BAD: Unprotected mutation of global state
	globalSecret = newSecret
}

// ===========================
// 30. EVAL-LIKE VULNERABILITY
// ===========================
func executeCodeFromString(codeString string) {
	// BAD: Simulating code execution from string
	// In real Go, this would use reflection or similar
	fmt.Println("Executing:", codeString)
	// This is dangerous if codeString comes from untrusted source
}

// ===========================
// 31. WEAK SESSION MANAGEMENT
// ===========================
var sessions = make(map[string]string)

func createSession(username string) string {
	// BAD: Using simple timestamp as session ID
	sessionID := fmt.Sprintf("session_%d", time.Now().Unix())
	sessions[sessionID] = username
	return sessionID
}

func getSessionUser(sessionID string) (string, error) {
	// BAD: No session expiration or validation
	if user, exists := sessions[sessionID]; exists {
		return user, nil
	}
	return "", fmt.Errorf("session not found")
}

// ===========================
// 32. LACK OF INPUT CONSTRAINTS
// ===========================
func downloadFile(w http.ResponseWriter, r *http.Request) error {
	// BAD: No limit on file size or processing time
	filePath := r.URL.Query().Get("file")
	
	// BAD: No path validation
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(filePath)))
	w.Write(data)
	return nil
}

// ===========================
// 33. INSECURE COOKIE HANDLING
// ===========================
func handleLoginInsecure(w http.ResponseWriter, r *http.Request) error {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if _, err := vulnerableLogin(username, password); err == nil {
		// BAD: Creating insecure cookies
		cookie := &http.Cookie{
			Name:     "auth_token",
			Value:    generateWeakToken(),
			Secure:   false,  // BAD: Should be true for HTTPS only
			HttpOnly: false,  // BAD: Should be true to prevent JavaScript access
			SameSite: http.SameSiteNone, // BAD: Should be Strict or Lax
		}
		http.SetCookie(w, cookie)
		w.Write([]byte("Logged in"))
		return nil
	}

	w.WriteHeader(http.StatusUnauthorized)
	return fmt.Errorf("login failed")
}

// ===========================
// 34. RESOURCE LEAK
// ===========================
func readFileWithResourceLeak(filename string) (string, error) {
	// BAD: File not properly closed if error occurs
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(file)
	if err != nil {
		// Resource leak: file not closed
		return "", err
	}

	file.Close()
	return string(data), nil
}

// ===========================
// 35. COMMAND LINE INJECTION
// ===========================
func executeCommandWithUserInput(userInput string) error {
	// BAD: Using string concatenation with shell
	cmd := exec.Command("sh", "-c", "echo "+userInput)
	return cmd.Run()
}

func main() {
	fmt.Println("Starting unsafe Go server...")

	// Setup routes
	http.HandleFunc("/admin-data", handleAdminDataRequest)
	http.HandleFunc("/user", handleGetUserData)
	http.HandleFunc("/redirect", handleUnvalidatedRedirect)
	http.HandleFunc("/comment", handleXSSVulnerability)
	http.HandleFunc("/sensitive", handleSensitiveConfig)
	http.HandleFunc("/error", handleErrorRequest)

	// BAD: Starting insecure server bound to 0.0.0.0
	startInsecureServer()
}
