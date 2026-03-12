"""
core/detectors/framework_misconfig.py
=====================================
Detect framework-specific production misconfigurations.

This detector intentionally focuses on high-signal Django/Flask settings
that are frequently left unsafe in AI-generated code.
"""

import re

from core.detectors.base import BaseDetector


class FrameworkMisconfigDetector(BaseDetector):
    _PRODUCTION_FILE_HINTS = (
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "wsgi.py",
    )

    _RULES = [
        {
            "rule_id": "django_debug_true",
            "framework": "django",
            "pattern": re.compile(r"^\s*DEBUG\s*=\s*True\b"),
            "description": "Django DEBUG=True exposes sensitive stack traces and internals in production.",
            "base_severity": "high",
            "fix_hint": "Set DEBUG=False for production and control debug mode via environment-specific settings.",
        },
        {
            "rule_id": "django_allowed_hosts_wildcard",
            "framework": "django",
            "pattern": re.compile(r"^\s*ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"][^\]]*\]"),
            "description": "Django ALLOWED_HOSTS includes wildcard '*', enabling host-header abuse.",
            "base_severity": "high",
            "fix_hint": "Restrict ALLOWED_HOSTS to explicit trusted domains (for example: ['api.example.com']).",
        },
        {
            "rule_id": "django_csrf_cookie_secure_false",
            "framework": "django",
            "pattern": re.compile(r"^\s*CSRF_COOKIE_SECURE\s*=\s*False\b"),
            "description": "CSRF_COOKIE_SECURE=False allows CSRF cookies over non-HTTPS transport.",
            "base_severity": "medium",
            "fix_hint": "Set CSRF_COOKIE_SECURE=True when serving over HTTPS.",
        },
        {
            "rule_id": "django_session_cookie_secure_false",
            "framework": "django",
            "pattern": re.compile(r"^\s*SESSION_COOKIE_SECURE\s*=\s*False\b"),
            "description": "SESSION_COOKIE_SECURE=False allows session cookies over non-HTTPS transport.",
            "base_severity": "medium",
            "fix_hint": "Set SESSION_COOKIE_SECURE=True when serving over HTTPS.",
        },
        {
            "rule_id": "flask_app_run_debug_true",
            "framework": "flask",
            "pattern": re.compile(r"\bapp\.run\s*\([^)]*\bdebug\s*=\s*True\b"),
            "description": "Flask app.run(debug=True) enables debugger and interactive traceback in production.",
            "base_severity": "high",
            "fix_hint": "Run Flask with debug disabled in production (debug=False) and use a production WSGI server.",
        },
        {
            "rule_id": "flask_app_debug_true",
            "framework": "flask",
            "pattern": re.compile(r"\bapp\.debug\s*=\s*True\b"),
            "description": "Flask app.debug=True enables debug mode and sensitive error output in production.",
            "base_severity": "high",
            "fix_hint": "Set app.debug=False in production and configure logging/monitoring instead of debug mode.",
        },
    ]

    def detect(self, code: str, language: str, filename: str = "") -> list[dict]:
        if language not in {"python", "generic"}:
            return []

        violations: list[dict] = []
        lines = code.split("\n")
        is_prod_like = self._is_production_like_file(filename)

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            for rule in self._RULES:
                if not rule["pattern"].search(line):
                    continue

                severity = rule["base_severity"]
                if rule["rule_id"] in {"django_debug_true", "flask_app_run_debug_true", "flask_app_debug_true"} and is_prod_like:
                    severity = "critical"

                violations.append(
                    {
                        "type": "framework_misconfiguration",
                        "severity": severity,
                        "line": line_num,
                        "description": rule["description"],
                        "offending_line": stripped,
                        "fix_hint": rule["fix_hint"],
                        "metadata": {
                            "framework": rule["framework"],
                            "rule_id": rule["rule_id"],
                        },
                    }
                )
                break

        return violations

    def _is_production_like_file(self, filename: str) -> bool:
        normalized = (filename or "").replace("\\", "/").lower()
        return any(hint in normalized for hint in self._PRODUCTION_FILE_HINTS)
