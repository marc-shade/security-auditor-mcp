"""
Pytest configuration and fixtures for security-auditor-mcp tests
"""

import pytest
from pathlib import Path
import tempfile
import shutil
from security_auditor import SecurityAuditor, Vulnerability, Severity


@pytest.fixture
def auditor():
    """Create SecurityAuditor instance"""
    return SecurityAuditor()


@pytest.fixture
def temp_dir():
    """Create temporary directory for test files"""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def vulnerable_sql_code():
    """Sample code with SQL injection vulnerability"""
    return '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection via string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
'''


@pytest.fixture
def safe_sql_code():
    """Sample code with safe SQL queries"""
    return '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
'''


@pytest.fixture
def vulnerable_command_code():
    """Sample code with command injection"""
    return '''
import subprocess
import os

def process_file(filename):
    # VULNERABLE: Command injection with shell=True
    subprocess.run(f"cat {filename}", shell=True)
    os.system("rm " + filename)
'''


@pytest.fixture
def vulnerable_path_traversal():
    """Sample code with path traversal"""
    return '''
def read_file(user_path):
    # VULNERABLE: Path traversal
    with open("/var/data/" + user_path, 'r') as f:
        return f.read()
'''


@pytest.fixture
def hardcoded_secrets():
    """Sample code with hardcoded credentials"""
    return '''
# VULNERABLE: Hardcoded credentials
API_KEY = "FAKE_API_KEY_NOT_REAL_TESTING_ONLY_123"
DB_PASSWORD = "MySecretPassword123"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
'''


@pytest.fixture
def weak_crypto_code():
    """Sample code with weak cryptography"""
    return '''
import hashlib

def hash_password(password):
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()
    
def verify_password(password, stored_hash):
    # VULNERABLE: SHA1 is deprecated
    return hashlib.sha1(password.encode()).hexdigest() == stored_hash
'''


@pytest.fixture
def owasp_test_vectors():
    """OWASP Top 10 test vectors"""
    return {
        'sql_injection': [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "admin'--",
            "' UNION SELECT NULL--",
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
        ],
        'command_injection': [
            "; cat /etc/passwd",
            "| ls -la",
            "& whoami",
            "`id`",
        ],
    }


@pytest.fixture
def sample_vulnerability():
    """Create sample Vulnerability object"""
    return Vulnerability(
        file_path="/test/vulnerable.py",
        line_number=10,
        severity=Severity.HIGH,
        description="SQL injection vulnerability",
        suggested_fix="Use parameterized queries",
        code_snippet="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        cwe_id="CWE-89"
    )


@pytest.fixture
def mixed_codebase(temp_dir):
    """Create test codebase with mixed vulnerabilities"""
    # Vulnerable Python file
    vuln_py = temp_dir / "vulnerable.py"
    vuln_py.write_text('''
import sqlite3
password = "hardcoded_secret_123"
query = "SELECT * FROM users WHERE name = " + user_input
cursor.execute(query)
''')
    
    # Safe Python file
    safe_py = temp_dir / "safe.py"
    safe_py.write_text('''
import sqlite3
password = os.environ.get("DB_PASSWORD")
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
''')
    
    # Vulnerable JS file
    vuln_js = temp_dir / "app.js"
    vuln_js.write_text('''
const password = "secret123";
element.innerHTML = userInput;
''')
    
    return temp_dir


@pytest.fixture
def security_test_cases():
    """Comprehensive security test cases"""
    return {
        'sql_injection_cases': [
            ('cursor.execute("SELECT * FROM t WHERE id = " + uid)', True),
            ('cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))', False),
            ('query = "DELETE FROM users WHERE " + condition', True),
            ('conn.execute(f"SELECT {column} FROM table")', True),
        ],
        'command_injection_cases': [
            ('os.system("rm " + filename)', True),
            ('subprocess.run(cmd, shell=True)', True),
            ('subprocess.run(["ls", path])', False),
            ('exec("import " + module)', True),
        ],
        'path_traversal_cases': [
            ('open(base_path + user_file)', True),
            ('Path("/data/" + filename)', True),
            ('file_path = "../../../etc/passwd"', True),
            ('open(safe_path)', False),
        ],
        'secrets_cases': [
            ('api_key = "TESTKEY_1234567890123456789012"', True),
            ('password = "MyPassword123"', True),
            ('secret = "verylongsecretkey123456"', True),
            ('api_key = os.getenv("API_KEY")', False),
        ],
        'crypto_cases': [
            ('hashlib.md5(data)', True),
            ('hashlib.sha1(password)', True),
            ('hashlib.sha256(data)', False),
            ('hashlib.sha512(password)', False),
        ],
    }
