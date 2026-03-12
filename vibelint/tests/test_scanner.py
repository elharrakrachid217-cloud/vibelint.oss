"""
tests/test_scanner.py
=====================
Run these tests to verify your scanner is working.

How to run:
    pip install pytest
    pytest tests/ -v

Every time you add a new detection pattern, add a test here first.
This is your safety net — it ensures you never accidentally break a detector.
"""

import pytest
from core.scanner import SecurityScanner

scanner = SecurityScanner()


# ─────────────────────────────────────────
# SECRETS DETECTION TESTS
# ─────────────────────────────────────────

def test_detects_hardcoded_openai_key():
    """The most common vibe coding vulnerability."""
    code = 'api_key = "sk-abc123def456ghi789jkl012mno345pqr"'
    result = scanner.scan(code=code, filename="app.py", language="python")
    assert result["approved"] is False
    assert any(v["type"] == "hard_coded_secret" for v in result["violations"])


def test_detects_hardcoded_aws_key():
    code = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    result = scanner.scan(code=code, filename="config.py", language="python")
    assert result["approved"] is False
    assert result["violations"][0]["severity"] == "critical"


def test_detects_hardcoded_database_url():
    code = 'DATABASE_URL = "postgres://admin:mypassword123@localhost/mydb"'
    result = scanner.scan(code=code, filename="settings.py", language="python")
    assert result["approved"] is False


def test_clean_env_var_usage_passes():
    """Code that uses env vars should pass — no false positives."""
    code = 'API_KEY = os.environ.get("OPENAI_API_KEY")'
    result = scanner.scan(code=code, filename="app.py", language="python")
    assert result["approved"] is True


def test_example_env_file_passes():
    """Placeholder values in examples should not trigger."""
    code = 'api_key = "YOUR_KEY_HERE"'
    result = scanner.scan(code=code, filename="example.py", language="python")
    assert result["approved"] is True


# ─────────────────────────────────────────
# AUTH DETECTION TESTS
# ─────────────────────────────────────────

def test_detects_md5_password_hashing():
    code = 'hashed = hashlib.md5(password.encode()).hexdigest()'
    result = scanner.scan(code=code, filename="auth.py", language="python")
    assert result["approved"] is False
    assert any(v["type"] == "insecure_auth" for v in result["violations"])


def test_detects_jwt_without_verification():
    code = 'payload = jwt.decode(token, options={"verify": False})'
    result = scanner.scan(code=code, filename="auth.py", language="python")
    assert result["approved"] is False


def test_detects_sha1_password_hashing():
    code = 'password_hash = hashlib.sha1(password.encode()).hexdigest()'
    result = scanner.scan(code=code, filename="auth.py", language="python")
    assert result["approved"] is False


# ─────────────────────────────────────────
# INJECTION DETECTION TESTS
# ─────────────────────────────────────────

def test_detects_sql_fstring_injection():
    """Classic AI-generated SQL injection."""
    code = f'cursor.execute(f"SELECT * FROM users WHERE id = {{user_id}}")'
    result = scanner.scan(code=code, filename="db.py", language="python")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_detects_sql_format_injection():
    code = 'query = "SELECT * FROM users WHERE name = {}".format(username)'
    result = scanner.scan(code=code, filename="db.py", language="python")
    assert result["approved"] is False


def test_detects_xss_innerhtml():
    code = 'element.innerHTML = "<p>" + userInput + "</p>";'
    result = scanner.scan(code=code, filename="app.js", language="javascript")
    assert result["approved"] is False


def test_clean_parameterized_query_passes():
    """Properly written SQL should not trigger false positives."""
    code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
    result = scanner.scan(code=code, filename="db.py", language="python")
    assert result["approved"] is True


# ─────────────────────────────────────────
# REMEDIATION TESTS
# ─────────────────────────────────────────

def test_remediator_replaces_secret_with_env_var():
    """The fixed code should reference os.environ, not the raw secret."""
    code = 'API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"'
    result = scanner.scan(code=code, filename="app.py", language="python")
    assert "os.environ.get" in result["remediated_code"]
    assert "sk-abc123" not in result["remediated_code"]


def test_remediator_adds_comment_for_auth_issues():
    """Auth issues should get a warning comment in the remediated code."""
    code = 'hashed = hashlib.md5(password.encode()).hexdigest()'
    result = scanner.scan(code=code, filename="auth.py", language="python")
    assert "VIBELINT" in result["remediated_code"]


# ─────────────────────────────────────────
# SUMMARY / STATS TESTS
# ─────────────────────────────────────────

def test_summary_contains_violation_count():
    code = 'API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"'
    result = scanner.scan(code=code, filename="app.py", language="python")
    assert "1" in result["summary"]


def test_clean_code_shows_approved_summary():
    code = 'def add(a, b):\n    return a + b'
    result = scanner.scan(code=code, filename="utils.py", language="python")
    assert result["approved"] is True
    assert "✅" in result["summary"]


# Rate limiting and prompt injection tests omitted in free version (paid detectors).


def test_scanner_flags_framework_misconfig_and_disapproves():
    code = """
DEBUG = True
"""
    result = scanner.scan(code=code, filename="settings.py", language="python")
    assert result["approved"] is False
    assert any(v["type"] == "framework_misconfiguration" for v in result["violations"])


def test_scanner_remediator_adds_comment_for_framework_misconfig():
    code = """
from flask import Flask
app = Flask(__name__)
app.run(debug=True)
"""
    result = scanner.scan(code=code, filename="app.py", language="python")
    assert any(v["type"] == "framework_misconfiguration" for v in result["violations"])
    assert "VIBELINT" in result["remediated_code"]
