const express = require('express');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const mysql = require('mysql');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ===========================
// 1. SQL INJECTION VULNERABILITY
// ===========================
app.get('/vulnerable-sql', (req, res) => {
  const userId = req.query.id;
  
  // BAD: Direct string concatenation in SQL query
  const query = "SELECT * FROM users WHERE id = " + userId;
  
  // This allows SQL injection like: /vulnerable-sql?id=1 OR 1=1
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// ===========================
// 2. COMMAND INJECTION VULNERABILITY
// ===========================
app.get('/vulnerable-exec', (req, res) => {
  const filename = req.query.file;
  
  // BAD: Direct user input in shell command
  exec('cat ' + filename, (error, stdout, stderr) => {
    if (error) {
      res.status(400).send(error.message);
      return;
    }
    res.send(stdout);
  });
  
  // This allows command injection like: /vulnerable-exec?file=test.txt; rm -rf /
});

// ===========================
// 3. PATH TRAVERSAL VULNERABILITY
// ===========================
app.get('/vulnerable-file-read', (req, res) => {
  const filePath = req.query.path;
  
  // BAD: No validation of file path
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(400).send(err.message);
      return;
    }
    res.send(data);
  });
  
  // This allows path traversal like: /vulnerable-file-read?path=../../../../etc/passwd
});

// ===========================
// 4. HARDCODED CREDENTIALS
// ===========================
const DB_CONFIG = {
  host: 'localhost',
  user: 'admin',
  password: 'SuperSecretPassword123!', 
  database: 'myapp_db'
};

const API_KEY = 'sk_live_51234567890abcdefghijk'; 
const SECRET_TOKEN = 'my-super-secret-key-123'; 

// ===========================
// 5. WEAK CRYPTOGRAPHY
// ===========================
function hashPassword(password) {
  // BAD: Using MD5 which is cryptographically broken
  return crypto.createHash('md5').update(password).digest('hex');
}

function encryptData(data, key) {
  // BAD: Using basic XOR encryption
  let encrypted = '';
  for (let i = 0; i < data.length; i++) {
    encrypted += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return encrypted;
}

// ===========================
// 6. WEAK RANDOM NUMBER GENERATION
// ===========================
function generateSessionToken() {
  // BAD: Using Math.random() for security-sensitive values
  return Math.random().toString(36).substring(2, 15);
}

function generateResetToken() {
  // BAD: Using Date.now() as a token
  return 'reset_' + Date.now();
}

// ===========================
// 7. UNVALIDATED REDIRECTS
// ===========================
app.get('/redirect', (req, res) => {
  const redirectUrl = req.query.url;
  
  // BAD: No validation of redirect URL
  res.redirect(redirectUrl);
  
  // This allows open redirect like: /redirect?url=http://malicious.com
});

// ===========================
// 8. XSS VULNERABILITY
// ===========================
app.get('/vulnerable-xss', (req, res) => {
  const userInput = req.query.comment;
  
  // BAD: Directly rendering user input without escaping
  const html = `
    <html>
      <body>
        <h1>Comment:</h1>
        <p>${userInput}</p>
      </body>
    </html>
  `;
  
  res.send(html);
  
  // This allows XSS like: /vulnerable-xss?comment=<script>alert('XSS')</script>
});

// ===========================
// 9. INSECURE DESERIALIZATION
// ===========================
app.post('/vulnerable-deserialize', (req, res) => {
  const data = req.body.data;
  
  // BAD: Using eval on user-supplied data
  const result = eval('(' + data + ')');
  
  res.json(result);
});

// ===========================
// 10. BROKEN AUTHENTICATION
// ===========================
app.post('/vulnerable-login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // BAD: Storing passwords in plain text
  const users = {
    'admin': 'password123',
    'user': 'mypassword'
  };
  
  if (users[username] === password) {
    // BAD: Session token is too simple
    const token = username + '_token_' + Date.now();
    res.json({ success: true, token: token });
  } else {
    res.json({ success: false });
  }
});

// ===========================
// 11. RACE CONDITION
// ===========================
app.post('/vulnerable-transfer', (req, res) => {
  const userId = req.body.userId;
  const amount = req.body.amount;
  
  // BAD: Check-then-act pattern without proper locking
  const query = `SELECT balance FROM accounts WHERE id = ${userId}`;
  
  db.query(query, (err, results) => {
    if (results[0].balance >= amount) {
      // Time window for race condition exists here
      const updateQuery = `UPDATE accounts SET balance = balance - ${amount} WHERE id = ${userId}`;
      db.query(updateQuery);
      res.json({ success: true });
    }
  });
});

// ===========================
// 12. MISSING AUTHENTICATION
// ===========================
app.get('/public-admin-data', (req, res) => {
  // BAD: No authentication check on sensitive endpoint
  const adminData = {
    users: 'all_users_data',
    secrets: 'sensitive_info'
  };
  
  res.json(adminData);
});

// ===========================
// 13. INSECURE DIRECT OBJECT REFERENCES (IDOR)
// ===========================
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  
  // BAD: No authorization check - user can access any other user's data
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// ===========================
// 14. UNSAFE REGULAR EXPRESSIONS (ReDoS)
// ===========================
function validateEmail(email) {
  // BAD: Regex vulnerable to ReDoS (Regular Expression Denial of Service)
  const regex = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return regex.test(email);
}

function validateUrl(url) {
  // BAD: Overly complex regex that can cause ReDoS
  const regex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
  return regex.test(url);
}

// ===========================
// 15. INSECURE HTTP
// ===========================
// BAD: Not using HTTPS
app.listen(8080, () => {
  console.log('Server listening on port 8080');
});

// ===========================
// 16. UNPROTECTED SENSITIVE DATA
// ===========================
function getUserData(userId) {
  // BAD: Returning sensitive data without filtering
  const userData = {
    id: userId,
    name: 'John Doe',
    email: 'john@example.com',
    ssn: '123-45-6789', // Should not be returned to client
    creditCard: '1234-5678-9012-3456', // Should not be returned to client
    passwordHash: 'hash_value' // Should not be returned to client
  };
  
  return userData;
}

// ===========================
// 17. MISSING ERROR HANDLING
// ===========================
app.get('/no-error-handling', (req, res) => {
  // BAD: No try-catch or error handling
  const data = JSON.parse(req.body.data);
  const result = data.field.nested.value; // Potential null pointer exception
  res.json(result);
});

// ===========================
// 18. USING DEPRECATED FUNCTIONS
// ===========================
function oldHashFunction(password) {
  // BAD: Using deprecated crypto functions
  return crypto.createHash('sha1').update(password).digest('hex');
}

// ===========================
// 19. HARDCODED DATABASE CONNECTION
// ===========================
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root123', // BAD: Hardcoded password
  database: 'test_db'
});

// ===========================
// 20. INSUFFICIENT LOGGING
// ===========================
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // BAD: No audit logging of authentication attempts
  // BAD: Logging sensitive data
  console.log(`User ${username} attempted login with password ${password}`);
  
  res.json({ success: true });
});

module.exports = app;
