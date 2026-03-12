"""
tests/test_framework_misconfig.py
=================================
Tests for framework-specific misconfiguration detection (Django/Flask).
"""

from core.scanner import SecurityScanner

scanner = SecurityScanner()


def _misconfig_findings(result: dict) -> list[dict]:
    return [v for v in result["violations"] if v["type"] == "framework_misconfiguration"]


def test_django_debug_true_in_settings_is_critical():
    code = """
DEBUG = True
SECRET_KEY = "unsafe"
"""
    result = scanner.scan(code=code, filename="settings.py", language="python")
    findings = _misconfig_findings(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["metadata"]["framework"] == "django"


def test_django_allowed_hosts_wildcard_flagged_high():
    code = """
ALLOWED_HOSTS = ["*"]
"""
    result = scanner.scan(code=code, filename="settings.py", language="python")
    findings = _misconfig_findings(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_django_cookie_secure_false_flags_medium():
    code = """
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
"""
    result = scanner.scan(code=code, filename="settings.py", language="python")
    findings = _misconfig_findings(result)
    assert len(findings) == 2
    assert all(v["severity"] == "medium" for v in findings)


def test_flask_debug_true_in_prod_config_is_critical():
    code = """
from flask import Flask
app = Flask(__name__)
app.debug = True
"""
    result = scanner.scan(code=code, filename="production.py", language="python")
    findings = _misconfig_findings(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["metadata"]["framework"] == "flask"


def test_flask_app_run_debug_true_flagged():
    code = """
from flask import Flask
app = Flask(__name__)
app.run(debug=True)
"""
    result = scanner.scan(code=code, filename="app.py", language="python")
    findings = _misconfig_findings(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_safe_django_settings_not_flagged():
    code = """
DEBUG = False
ALLOWED_HOSTS = ["api.example.com", "admin.example.com"]
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
"""
    result = scanner.scan(code=code, filename="settings.py", language="python")
    assert _misconfig_findings(result) == []


def test_commented_lines_not_flagged():
    code = """
# DEBUG = True
# ALLOWED_HOSTS = ["*"]
# app.run(debug=True)
"""
    result = scanner.scan(code=code, filename="settings.py", language="python")
    assert _misconfig_findings(result) == []


def test_unrelated_javascript_file_not_flagged():
    code = """
const config = { debug: true };
"""
    result = scanner.scan(code=code, filename="config.js", language="javascript")
    assert _misconfig_findings(result) == []
