"""
tests/test_scanner_js.py
========================
JS/TS-specific security pattern tests.

Covers all new detection patterns added for JavaScript and TypeScript:
- Secrets: process.env fallback bypass, NextAuth secrets, NEXT_PUBLIC_ hardcoded
- Auth: localStorage JWT, fetch credentials in URL, NextAuth debug mode
- Injection: eval() with variables, document.write(), dangerouslySetInnerHTML
  without DOMPurify, prototype pollution
- Remediator: verifies JS/TS fix hints use process.env syntax
"""

import pytest
from core.scanner import SecurityScanner

scanner = SecurityScanner()


# ─────────────────────────────────────────
# SECRETS — JS/TS PATTERNS
# ─────────────────────────────────────────

def test_detects_process_env_fallback_bypass_js():
    code = 'const apiKey = process.env.API_KEY || "sk-default-fallback-key-12345"'
    result = scanner.scan(code=code, filename="config.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "hard_coded_secret" for v in result["violations"])


def test_detects_process_env_fallback_bypass_ts():
    code = 'const secret = process.env.SECRET_KEY || "my-hardcoded-fallback-secret"'
    result = scanner.scan(code=code, filename="config.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "hard_coded_secret" for v in result["violations"])


def test_detects_nextauth_secret_hardcoded_js():
    code = 'const NEXTAUTH_SECRET = "super-secret-nextauth-key-12345"'
    result = scanner.scan(code=code, filename="auth.config.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "hard_coded_secret" for v in result["violations"])


def test_detects_nextauth_secret_hardcoded_ts():
    code = 'NEXTAUTH_SECRET = "production-secret-value-abcdef"'
    result = scanner.scan(code=code, filename="auth.config.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "hard_coded_secret" for v in result["violations"])


def test_detects_next_public_var_hardcoded_js():
    code = 'const NEXT_PUBLIC_API_KEY = "pk_live_abc123def456ghi789"'
    result = scanner.scan(code=code, filename="config.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "hard_coded_secret" for v in result["violations"])


def test_detects_next_public_var_hardcoded_ts():
    code = 'const NEXT_PUBLIC_SUPABASE_URL = "https://abc.supabase.co/rest/v1"'
    result = scanner.scan(code=code, filename="config.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "hard_coded_secret" for v in result["violations"])


def test_clean_process_env_usage_passes_js():
    code = 'const apiKey = process.env.API_KEY'
    result = scanner.scan(code=code, filename="config.js", language="javascript")
    assert result["approved"] is True


# ─────────────────────────────────────────
# AUTH — JS/TS PATTERNS
# ─────────────────────────────────────────

def test_detects_localstorage_jwt_js():
    code = 'localStorage.setItem("token", jwtToken)'
    result = scanner.scan(code=code, filename="auth.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "insecure_auth" for v in result["violations"])


def test_detects_localstorage_jwt_ts():
    code = 'localStorage.setItem("access_token", response.token)'
    result = scanner.scan(code=code, filename="auth.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "insecure_auth" for v in result["violations"])


def test_detects_fetch_token_in_url_js():
    code = 'fetch("/api/data?token=" + authToken)'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "insecure_auth" for v in result["violations"])


def test_detects_fetch_token_in_url_ts():
    code = 'fetch(`/api/users?api_key=${key}`)'
    result = scanner.scan(code=code, filename="api.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "insecure_auth" for v in result["violations"])


def test_detects_nextauth_debug_enabled_js():
    code = 'const handler = NextAuth({ debug: true, providers: [] })'
    result = scanner.scan(code=code, filename="auth.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "insecure_auth" for v in result["violations"])


def test_detects_nextauth_debug_enabled_ts():
    code = 'export default NextAuth({ debug: true, secret: process.env.SECRET })'
    result = scanner.scan(code=code, filename="auth.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "insecure_auth" for v in result["violations"])


# ─────────────────────────────────────────
# INJECTION — JS/TS PATTERNS
# ─────────────────────────────────────────

def test_detects_eval_with_variable_js():
    code = 'const result = eval(userInput)'
    result = scanner.scan(code=code, filename="app.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_detects_eval_with_variable_ts():
    code = 'eval(dynamicCode)'
    result = scanner.scan(code=code, filename="app.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_detects_document_write_user_data_js():
    code = 'document.write("<h1>" + userName + "</h1>")'
    result = scanner.scan(code=code, filename="app.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_detects_document_write_user_data_ts():
    code = 'document.write(`<div>${userContent}</div>`)'
    result = scanner.scan(code=code, filename="app.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_detects_dangerouslysetinnerhtml_no_dompurify_js():
    code = '<div dangerouslySetInnerHTML={{ __html: userData }} />'
    result = scanner.scan(code=code, filename="App.jsx", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_detects_dangerouslysetinnerhtml_no_dompurify_ts():
    code = '<div dangerouslySetInnerHTML={{ __html: content }} />'
    result = scanner.scan(code=code, filename="App.tsx", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_dangerouslysetinnerhtml_with_dompurify_passes_js():
    code = '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userData) }} />'
    result = scanner.scan(code=code, filename="App.jsx", language="javascript")
    injection_violations = [v for v in result["violations"] if v["type"] == "injection_risk"]
    assert len(injection_violations) == 0


def test_dangerouslysetinnerhtml_with_dompurify_passes_ts():
    code = '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />'
    result = scanner.scan(code=code, filename="App.tsx", language="typescript")
    injection_violations = [v for v in result["violations"] if v["type"] == "injection_risk"]
    assert len(injection_violations) == 0


def test_detects_prototype_pollution_js():
    code = 'obj[userInput] = value'
    result = scanner.scan(code=code, filename="utils.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_detects_prototype_pollution_ts():
    code = 'target[reqBody] = payload'
    result = scanner.scan(code=code, filename="utils.ts", language="typescript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


# ─────────────────────────────────────────
# REMEDIATOR — JS/TS process.env SYNTAX
# ─────────────────────────────────────────

def test_remediator_js_secret_uses_process_env():
    code = 'const API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"'
    result = scanner.scan(code=code, filename="config.js", language="javascript")
    assert "process.env" in result["remediated_code"]
    assert "os.environ" not in result["remediated_code"]


def test_remediator_ts_secret_uses_process_env():
    code = 'const SECRET_KEY = "sk-abc123def456ghi789jkl012mno345pqr"'
    result = scanner.scan(code=code, filename="config.ts", language="typescript")
    assert "process.env" in result["remediated_code"]
    assert "os.environ" not in result["remediated_code"]


def test_remediator_js_fix_hint_not_python_syntax():
    code = 'const API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"'
    result = scanner.scan(code=code, filename="config.js", language="javascript")
    for v in result["violations"]:
        assert "os.environ" not in v["fix_hint"]
        assert "process.env" in v["fix_hint"]


def test_remediator_ts_fix_hint_not_python_syntax():
    code = 'const SECRET_KEY = "sk-abc123def456ghi789jkl012mno345pqr"'
    result = scanner.scan(code=code, filename="config.ts", language="typescript")
    for v in result["violations"]:
        assert "os.environ" not in v["fix_hint"]
        assert "process.env" in v["fix_hint"]
