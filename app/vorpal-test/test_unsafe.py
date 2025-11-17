"""
Sample code to test Checkmarx/Vorpal security scanning capabilities (Python)
This file contains various security vulnerabilities and bad practices
"""

import os
import sys
import pickle
import subprocess
import hashlib
import random
import string
from datetime import datetime
from flask import Flask, request, redirect, render_template_string
import mysql.connector
import jwt
import base64

app = Flask(__name__)

# ===========================
# 1. SQL INJECTION VULNERABILITY
# ===========================
@app.route('/vulnerable-sql')
def vulnerable_sql():
    """BAD: Direct string concatenation in SQL query"""
    user_id = request.args.get('id')
    
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    # This allows SQL injection like: /vulnerable-sql?id=1 OR 1=1
    try:
        db = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root123",
            database="test_db"
        )
        cursor = db.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        return results
    except Exception as e:
        return str(e)


# ===========================
# 2. COMMAND INJECTION VULNERABILITY
# ===========================
@app.route('/vulnerable-exec')
def vulnerable_exec():
    """BAD: Direct user input in shell command"""
    filename = request.args.get('file')
    
    # Command injection vulnerability
    command = f'cat {filename}'
    result = subprocess.check_output(command, shell=True)
    
    # This allows command injection like: /vulnerable-exec?file=test.txt; rm -rf /
    return result.decode('utf-8')


# ===========================
# 3. PATH TRAVERSAL VULNERABILITY
# ===========================
@app.route('/vulnerable-file-read')
def vulnerable_file_read():
    """BAD: No validation of file path"""
    file_path = request.args.get('path')
    
    # Path traversal vulnerability
    try:
        with open(file_path, 'r') as f:
            data = f.read()
        return data
    except Exception as e:
        return str(e)
    
    # This allows path traversal like: /vulnerable-file-read?path=../../../../etc/passwd


# ===========================
# 4. HARDCODED CREDENTIALS
# ===========================
DB_CONFIG = {
    'host': 'localhost',
    'user': 'admin',
    'password': 'SuperSecretPassword123!',  # BAD: Hardcoded password
    'database': 'myapp_db'
}

API_KEY = 'sk_live_51234567890abcdefghijk'  # BAD: Hardcoded API key
SECRET_TOKEN = 'my-super-secret-key-123'  # BAD: Hardcoded secret
JWT_SECRET = 'super_secret_jwt_key_12345'  # BAD: Hardcoded JWT secret

# ===========================
# 5. WEAK CRYPTOGRAPHY
# ===========================
def hash_password_weak(password):
    """BAD: Using MD5 which is cryptographically broken"""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    """BAD: Using SHA1 which is deprecated"""
    return hashlib.sha1(password.encode()).hexdigest()


def encrypt_data_weak(data, key):
    """BAD: Using basic XOR encryption"""
    encrypted = ''
    for i, char in enumerate(data):
        encrypted += chr(ord(char) ^ ord(key[i % len(key)]))
    return encrypted


def encrypt_with_base64(data):
    """BAD: Using base64 as encryption (not actually encryption)"""
    return base64.b64encode(data.encode()).decode()


# ===========================
# 6. WEAK RANDOM NUMBER GENERATION
# ===========================
def generate_session_token():
    """BAD: Using weak random for security-sensitive values"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=20))


def generate_reset_token():
    """BAD: Using timestamp as token"""
    return f'reset_{datetime.now().timestamp()}'


def generate_otp():
    """BAD: Using random.randint for security-sensitive OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


# ===========================
# 7. UNVALIDATED REDIRECTS
# ===========================
@app.route('/redirect')
def unvalidated_redirect():
    """BAD: No validation of redirect URL"""
    redirect_url = request.args.get('url')
    
    # No validation
    return redirect(redirect_url)
    
    # This allows open redirect like: /redirect?url=http://malicious.com


# ===========================
# 8. XSS VULNERABILITY
# ===========================
@app.route('/vulnerable-xss')
def vulnerable_xss():
    """BAD: Directly rendering user input without escaping"""
    user_input = request.args.get('comment')
    
    html = f"""
    <html>
      <body>
        <h1>Comment:</h1>
        <p>{user_input}</p>
      </body>
    </html>
    """
    
    return render_template_string(html)
    
    # This allows XSS like: /vulnerable-xss?comment=<script>alert('XSS')</script>


# ===========================
# 9. INSECURE DESERIALIZATION
# ===========================
@app.route('/vulnerable-deserialize', methods=['POST'])
def vulnerable_deserialize():
    """BAD: Using pickle on user-supplied data"""
    data = request.json.get('data')
    
    # Insecure deserialization
    result = pickle.loads(base64.b64decode(data))
    
    return result


@app.route('/vulnerable-eval', methods=['POST'])
def vulnerable_eval():
    """BAD: Using eval on user data"""
    code = request.json.get('code')
    
    # Extremely dangerous - using eval
    result = eval(code)
    
    return str(result)


# ===========================
# 10. BROKEN AUTHENTICATION
# ===========================
USERS = {
    'admin': 'password123',  # BAD: Plain text passwords
    'user': 'mypassword'
}


@app.route('/vulnerable-login', methods=['POST'])
def vulnerable_login():
    """BAD: Plain text password storage and weak token"""
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username in USERS and USERS[username] == password:
        # BAD: Session token is too simple
        token = f'{username}_token_{datetime.now().timestamp()}'
        return {'success': True, 'token': token}
    else:
        return {'success': False}


# ===========================
# 11. RACE CONDITION
# ===========================
@app.route('/vulnerable-transfer', methods=['POST'])
def vulnerable_transfer():
    """BAD: Check-then-act pattern without proper locking"""
    user_id = request.json.get('userId')
    amount = request.json.get('amount')
    
    # BAD: Race condition - no locking
    query = f"SELECT balance FROM accounts WHERE id = {user_id}"
    
    db = mysql.connector.connect(**DB_CONFIG)
    cursor = db.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    
    if result[0] >= amount:
        # Time window for race condition exists here
        update_query = f"UPDATE accounts SET balance = balance - {amount} WHERE id = {user_id}"
        cursor.execute(update_query)
        db.commit()
        return {'success': True}
    
    return {'success': False}


# ===========================
# 12. MISSING AUTHENTICATION
# ===========================
@app.route('/public-admin-data')
def public_admin_data():
    """BAD: No authentication check on sensitive endpoint"""
    admin_data = {
        'users': 'all_users_data',
        'secrets': 'sensitive_info',
        'database_config': DB_CONFIG
    }
    return admin_data


# ===========================
# 13. INSECURE DIRECT OBJECT REFERENCES (IDOR)
# ===========================
@app.route('/user/<user_id>')
def get_user(user_id):
    """BAD: No authorization check - user can access any other user's data"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    db = mysql.connector.connect(**DB_CONFIG)
    cursor = db.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    
    return results


# ===========================
# 14. SENSITIVE DATA EXPOSURE
# ===========================
def get_user_data(user_id):
    """BAD: Returning sensitive data without filtering"""
    user_data = {
        'id': user_id,
        'name': 'John Doe',
        'email': 'john@example.com',
        'ssn': '123-45-6789',  # Should not be returned to client
        'credit_card': '1234-5678-9012-3456',  # Should not be returned to client
        'password_hash': 'hash_value',  # Should not be returned to client
        'api_token': 'sk_live_abcdefgh123456'  # Should not be exposed
    }
    return user_data


# ===========================
# 15. INSECURE CONFIGURATION
# ===========================
app.config['SECRET_KEY'] = 'debug_secret_key'  # BAD: Hardcoded secret
app.config['DEBUG'] = True  # BAD: Debug mode in production
app.config['SESSION_COOKIE_SECURE'] = False  # BAD: Not using secure cookies
app.config['SESSION_COOKIE_HTTPONLY'] = False  # BAD: HttpOnly not set
app.config['PERMANENT_SESSION_LIFETIME'] = 24 * 60 * 60  # Long session lifetime


# ===========================
# 16. MISSING ERROR HANDLING
# ===========================
@app.route('/no-error-handling')
def no_error_handling():
    """BAD: No try-catch or error handling"""
    data = request.json.get('data')
    result = data['field']['nested']['value']  # Potential KeyError
    return result


# ===========================
# 17. INSECURE LOGGING
# ===========================
import logging

logging.basicConfig(filename='app.log', level=logging.DEBUG)


@app.route('/login-insecure', methods=['POST'])
def login_insecure():
    """BAD: Logging sensitive data"""
    username = request.json.get('username')
    password = request.json.get('password')
    
    # BAD: Logging passwords and sensitive data
    logging.info(f'User {username} attempted login with password {password}')
    logging.debug(f'Full request: {request.json}')
    
    return {'success': True}


# ===========================
# 18. USING DEPRECATED/INSECURE FUNCTIONS
# ===========================
def old_encrypt_method(data, key):
    """BAD: Using insecure encryption method"""
    # Simple XOR - not secure at all
    return ''.join([chr(ord(c) ^ ord(k)) for c, k in zip(data, key)])


def use_input_directly():
    """BAD: Using input directly without validation"""
    user_input = input("Enter value: ")
    os.system(f"echo {user_input}")  # Command injection risk


# ===========================
# 19. DATABASE CREDENTIALS IN CODE
# ===========================
db_connection = mysql.connector.connect(
    host='localhost',
    user='root',
    password='root123',  # BAD: Hardcoded password
    database='test_db'
)


# ===========================
# 20. INSUFFICIENT INPUT VALIDATION
# ===========================
@app.route('/process-data', methods=['POST'])
def process_data():
    """BAD: No input validation"""
    age = request.json.get('age')
    name = request.json.get('name')
    email = request.json.get('email')
    
    # No validation - direct use
    query = f"INSERT INTO users (age, name, email) VALUES ({age}, '{name}', '{email}')"
    
    return {'success': True}


# ===========================
# 21. INSECURE RANDOMNESS
# ===========================
def generate_token_insecure():
    """BAD: Predictable token generation"""
    return str(random.randint(1000, 9999))


def generate_verification_code():
    """BAD: Weak randomness for verification"""
    code = ''
    for _ in range(6):
        code += str(random.randint(0, 9))
    return code


# ===========================
# 22. RESOURCE EXHAUSTION
# ===========================
@app.route('/download')
def download_file():
    """BAD: No limit on file size or processing"""
    file_path = request.args.get('path')
    
    # No size validation - can lead to DoS
    with open(file_path, 'rb') as f:
        content = f.read()  # Could be huge
    
    return content


# ===========================
# 23. INFORMATION DISCLOSURE
# ===========================
@app.route('/error')
def error_handler():
    """BAD: Exposing detailed error information"""
    try:
        # Some operation that fails
        result = 1 / 0
    except Exception as e:
        # BAD: Returning full exception details
        import traceback
        return {
            'error': str(e),
            'traceback': traceback.format_exc(),
            'sys_version': sys.version
        }


# ===========================
# 24. JWT VULNERABILITIES
# ===========================
def create_jwt_token_weak(user_id):
    """BAD: Using weak secret for JWT"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow().timestamp() + 3600
    }
    # BAD: Secret is hardcoded and weak
    token = jwt.encode(payload, 'secret_key_123', algorithm='HS256')
    return token


def decode_jwt_unsafe(token):
    """BAD: Not verifying JWT properly"""
    # BAD: Decoding without verification
    decoded = jwt.decode(token, options={"verify_signature": False})
    return decoded


# ===========================
# 25. UNSAFE FILE OPERATIONS
# ===========================
@app.route('/upload', methods=['POST'])
def upload_file():
    """BAD: Unsafe file upload handling"""
    file = request.files.get('file')
    
    # BAD: No validation of filename or type
    file.save(f'uploads/{file.filename}')
    
    # BAD: Executing uploaded file
    os.system(f'python uploads/{file.filename}')
    
    return {'success': True}


if __name__ == '__main__':
    # BAD: Running with debug=True in production
    # BAD: No HTTPS configuration
    app.run(debug=True, host='0.0.0.0', port=5000)
