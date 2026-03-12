"""
tests/test_semgrep.py
=====================
Tests for the Semgrep data-flow detector.

The _parse_output tests run without semgrep installed.
The detect() tests mock subprocess.run so they also work everywhere.
One integration test class runs only when semgrep is on PATH.
"""

import json
import os
import shutil
import subprocess as sp
from unittest.mock import MagicMock, patch

import pytest

from core.detectors.semgrep import SemgrepDetector


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _make_semgrep_json(results):
    """Build a minimal semgrep JSON output string."""
    return json.dumps({
        "results": results,
        "errors": [],
        "paths": {"scanned": [], "skipped": []},
        "version": "1.60.0",
    })


def _make_result(check_id, message, severity, line, *, lines_text="", fix=""):
    """Build a single semgrep result entry."""
    extra = {
        "message": message,
        "severity": severity,
        "fingerprint": "abc123",
        "lines": lines_text,
        "metadata": {},
    }
    if fix:
        extra["fix"] = fix
    return {
        "check_id": check_id,
        "path": "/tmp/test.py",
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 40},
        "extra": extra,
    }


# ─────────────────────────────────────────
# _parse_output unit tests
# ─────────────────────────────────────────

class TestParseOutput:
    detector = SemgrepDetector()

    def test_empty_results(self):
        raw = _make_semgrep_json([])
        violations = self.detector._parse_output(raw, "x = 1")
        assert violations == []

    def test_single_finding(self):
        code = "import os\nos.system('ls ' + user_input)"
        result = _make_result(
            "python.lang.security.audit.dangerous-system-call",
            "Found dynamic content used in a system call.",
            "ERROR",
            2,
            lines_text="os.system('ls ' + user_input)",
        )
        raw = _make_semgrep_json([result])
        violations = self.detector._parse_output(raw, code)

        assert len(violations) == 1
        v = violations[0]
        assert v["type"] == "semgrep_finding"
        assert v["severity"] == "high"
        assert v["line"] == 2
        assert "system call" in v["description"]
        assert v["offending_line"] == "os.system('ls ' + user_input)"

    def test_severity_mapping_critical(self):
        raw = _make_semgrep_json([
            _make_result("r.c", "Crit", "CRITICAL", 1),
        ])
        v = self.detector._parse_output(raw, "x = 1")
        assert v[0]["severity"] == "critical"

    def test_severity_mapping_high(self):
        raw = _make_semgrep_json([
            _make_result("r.h", "High", "HIGH", 1),
        ])
        v = self.detector._parse_output(raw, "x = 1")
        assert v[0]["severity"] == "high"

    def test_severity_mapping_error_to_high(self):
        raw = _make_semgrep_json([
            _make_result("r.e", "Error", "ERROR", 1),
        ])
        v = self.detector._parse_output(raw, "x = 1")
        assert v[0]["severity"] == "high"

    def test_severity_mapping_warning_to_medium(self):
        raw = _make_semgrep_json([
            _make_result("r.w", "Warn", "WARNING", 1),
        ])
        v = self.detector._parse_output(raw, "x = 1")
        assert v[0]["severity"] == "medium"

    def test_severity_mapping_low(self):
        raw = _make_semgrep_json([
            _make_result("r.l", "Low", "LOW", 1),
        ])
        v = self.detector._parse_output(raw, "x = 1")
        assert v[0]["severity"] == "low"

    def test_deduplicates_by_line(self):
        code = "os.system(cmd)"
        results = [
            _make_result("rule.a", "Finding A", "ERROR", 1),
            _make_result("rule.b", "Finding B", "WARNING", 1),
        ]
        raw = _make_semgrep_json(results)
        violations = self.detector._parse_output(raw, code)
        assert len(violations) == 1

    def test_invalid_json_returns_empty(self):
        violations = self.detector._parse_output("not json at all", "x = 1")
        assert violations == []

    def test_fix_hint_uses_semgrep_fix_when_available(self):
        code = "eval(user_input)"
        result = _make_result(
            "rule.eval", "Eval is dangerous", "ERROR", 1,
            fix="Use ast.literal_eval() instead",
        )
        raw = _make_semgrep_json([result])
        violations = self.detector._parse_output(raw, code)
        assert violations[0]["fix_hint"] == "Use ast.literal_eval() instead"

    def test_fix_hint_fallback_includes_rule_id(self):
        code = "eval(user_input)"
        result = _make_result("rule.eval", "Eval is dangerous", "ERROR", 1)
        raw = _make_semgrep_json([result])
        violations = self.detector._parse_output(raw, code)
        assert "rule.eval" in violations[0]["fix_hint"]

    def test_offending_line_falls_back_to_extra_lines(self):
        result = _make_result(
            "rule.x", "Bad", "ERROR", 99,
            lines_text="fallback line content",
        )
        raw = _make_semgrep_json([result])
        violations = self.detector._parse_output(raw, "short code")
        assert violations[0]["offending_line"] == "fallback line content"

    def test_violation_dict_has_all_required_keys(self):
        raw = _make_semgrep_json([
            _make_result("rule.x", "Msg", "HIGH", 1),
        ])
        v = self.detector._parse_output(raw, "x = 1")[0]
        for key in ("type", "severity", "line", "description", "offending_line", "fix_hint"):
            assert key in v, f"Missing key: {key}"


# ─────────────────────────────────────────
# detect() tests with mocked subprocess
# ─────────────────────────────────────────

class TestDetectMocked:

    def test_returns_empty_when_semgrep_not_installed(self):
        detector = SemgrepDetector()
        with patch("core.detectors.semgrep._semgrep_bin", None):
            SemgrepDetector._warned_missing = False
            result = detector.detect("os.system(cmd)", "python")
            assert result == []

    def test_warns_once_when_missing(self):
        detector = SemgrepDetector()
        with patch("core.detectors.semgrep._semgrep_bin", None):
            SemgrepDetector._warned_missing = False
            detector.detect("x = 1", "python")
            assert SemgrepDetector._warned_missing is True
            detector.detect("y = 2", "python")

    def test_calls_semgrep_and_parses_output(self):
        code = "import os\nos.system(cmd)"
        finding = _make_result(
            "python.lang.security.audit.dangerous-system-call",
            "Dynamic content in system call",
            "ERROR",
            2,
        )
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = _make_semgrep_json([finding])
        mock_proc.stderr = ""

        detector = SemgrepDetector()
        with patch("core.detectors.semgrep._semgrep_bin", "/usr/bin/semgrep"):
            with patch("core.detectors.semgrep.subprocess.run", return_value=mock_proc):
                violations = detector.detect(code, "python")

        assert len(violations) == 1
        assert violations[0]["type"] == "semgrep_finding"

    def test_returns_empty_on_exit_code_2(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stderr = "config error"

        detector = SemgrepDetector()
        with patch("core.detectors.semgrep._semgrep_bin", "/usr/bin/semgrep"):
            with patch("core.detectors.semgrep.subprocess.run", return_value=mock_proc):
                violations = detector.detect("x = 1", "python")

        assert violations == []

    def test_returns_empty_on_timeout(self):
        detector = SemgrepDetector()
        with patch("core.detectors.semgrep._semgrep_bin", "/usr/bin/semgrep"):
            with patch(
                "core.detectors.semgrep.subprocess.run",
                side_effect=sp.TimeoutExpired("semgrep", 60),
            ):
                violations = detector.detect("x = 1", "python")

        assert violations == []

    def test_returns_empty_on_unexpected_exception(self):
        detector = SemgrepDetector()
        with patch("core.detectors.semgrep._semgrep_bin", "/usr/bin/semgrep"):
            with patch(
                "core.detectors.semgrep.subprocess.run",
                side_effect=OSError("boom"),
            ):
                violations = detector.detect("x = 1", "python")

        assert violations == []

    def test_clean_scan_returns_no_violations(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = _make_semgrep_json([])
        mock_proc.stderr = ""

        detector = SemgrepDetector()
        with patch("core.detectors.semgrep._semgrep_bin", "/usr/bin/semgrep"):
            with patch("core.detectors.semgrep.subprocess.run", return_value=mock_proc):
                violations = detector.detect("def add(a, b): return a + b", "python")

        assert violations == []

    def test_custom_ruleset_passed_to_subprocess(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = _make_semgrep_json([])
        mock_proc.stderr = ""

        detector = SemgrepDetector(ruleset="p/python")
        with patch("core.detectors.semgrep._semgrep_bin", "/usr/bin/semgrep"):
            with patch("core.detectors.semgrep.subprocess.run", return_value=mock_proc) as mock_run:
                detector.detect("x = 1", "python")

        call_args = mock_run.call_args[0][0]
        assert "--config" in call_args
        config_idx = call_args.index("--config")
        assert call_args[config_idx + 1] == "p/python"

    def test_multiple_configs_passed_to_subprocess(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = _make_semgrep_json([])
        mock_proc.stderr = ""

        detector = SemgrepDetector(ruleset=["p/security-audit", "/path/to/rules"])
        with patch("core.detectors.semgrep._semgrep_bin", "/usr/bin/semgrep"):
            with patch("core.detectors.semgrep.subprocess.run", return_value=mock_proc) as mock_run:
                detector.detect("x = 1", "python")

        call_args = mock_run.call_args[0][0]
        assert call_args.count("--config") == 2
        assert "p/security-audit" in call_args
        assert "/path/to/rules" in call_args

    def test_nosql_insert_one_finding_passed_through(self):
        """When Semgrep returns a NoSQL finding (e.g. for insert_one), detector passes it through."""
        code = (
            "def handler(request):\n"
            "    data = request.json\n"
            "    db.users.insert_one(data)\n"
        )
        finding = _make_result(
            "nosql-injection-python",
            "Potential NoSQL injection detected. User-controlled data is passed to a database query without sanitization.",
            "ERROR",
            3,
        )
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = _make_semgrep_json([finding])
        mock_proc.stderr = ""

        detector = SemgrepDetector()
        with patch("core.detectors.semgrep._semgrep_bin", "/usr/bin/semgrep"):
            with patch("core.detectors.semgrep.subprocess.run", return_value=mock_proc):
                violations = detector.detect(code, "python")

        assert len(violations) >= 1
        has_nosql = any(
            v["type"] == "semgrep_finding"
            and ("nosql" in v["description"].lower() or "injection" in v["description"].lower())
            for v in violations
        )
        assert has_nosql


# ─────────────────────────────────────────
# Integration test (only when semgrep is on PATH)
# ─────────────────────────────────────────

_has_semgrep = shutil.which("semgrep") is not None
_run_semgrep_integration = os.getenv("RUN_SEMGREP_INTEGRATION_TESTS") == "1"


@pytest.mark.skipif(
    not (_has_semgrep and _run_semgrep_integration),
    reason="Set RUN_SEMGREP_INTEGRATION_TESTS=1 and install semgrep to run integration tests",
)
class TestSemgrepIntegration:

    def test_detects_dangerous_system_call(self):
        code = (
            'import os\n'
            'user_input = input("Enter: ")\n'
            'os.system("ls " + user_input)\n'
        )
        detector = SemgrepDetector()
        violations = detector.detect(code, "python")
        assert len(violations) >= 1
        assert any(
            "system" in v["description"].lower()
            or "command" in v["description"].lower()
            for v in violations
        )

    def test_clean_code_returns_no_findings(self):
        code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        detector = SemgrepDetector()
        violations = detector.detect(code, "python")
        assert violations == []

    def test_detects_nosql_injection(self):
        code = (
            "import os\n"
            "def handler(request):\n"
            "    data = request.json\n"
            "    db.users.find(data)\n"
        )
        detector = SemgrepDetector()
        violations = detector.detect(code, "python")
        assert len(violations) >= 1
        has_nosql = any(
            v["type"] == "semgrep_finding"
            and ("nosql" in v["description"].lower() or "injection" in v["description"].lower())
            for v in violations
        )
        assert has_nosql

    def test_detects_nosql_insert_one(self):
        """NoSQL rule flags request data passed to insert_one (integration, requires semgrep)."""
        code = (
            "def handler(request):\n"
            "    data = request.json\n"
            "    db.users.insert_one(data)\n"
        )
        detector = SemgrepDetector()
        violations = detector.detect(code, "python")
        assert len(violations) >= 1
        has_nosql = any(
            v["type"] == "semgrep_finding"
            and ("nosql" in v["description"].lower() or "injection" in v["description"].lower())
            for v in violations
        )
        assert has_nosql
