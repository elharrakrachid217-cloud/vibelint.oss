"""
core/scanner.py
===============
The brain of VibeLint.

Takes raw code as input, runs it through all detectors,
and returns a structured result with violations + auto-fixes.

This is where you'll spend most of your development time.
Each detector is in its own file so they're easy to expand.
"""

from core.detectors.secrets import SecretsDetector
from core.detectors.auth import AuthDetector
from core.detectors.injection import InjectionDetector
from core.detectors.cors import CorsDetector
from core.detectors.framework_misconfig import FrameworkMisconfigDetector
from core.detectors.semgrep import SemgrepDetector
from core.remediator import Remediator


class SecurityScanner:
    def __init__(self):
        self.detectors = [
            SecretsDetector(),
            AuthDetector(),
            InjectionDetector(),
            CorsDetector(),
            FrameworkMisconfigDetector(),
            SemgrepDetector(),
        ]
        self.remediator = Remediator()

    def scan(self, code: str, filename: str, language: str) -> dict:
        """
        Main scan method. Called for every AI-generated code block.

        Returns:
        {
            "approved": true/false,
            "filename": "auth.py",
            "violations": [
                {
                    "type": "hard_coded_secret",
                    "severity": "critical",
                    "line": 5,
                    "description": "API key hard-coded in source",
                    "fix_hint": "Move to .env and use os.environ.get('OPENAI_API_KEY')"
                }
            ],
            "remediated_code": "... fixed version of the code ...",
            "summary": "1 critical violation found and auto-fixed."
        }
        """
        all_violations = []

        # Run each detector
        for detector in self.detectors:
            try:
                violations = detector.detect(code=code, language=language, filename=filename)
            except TypeError:
                # Backward compatibility for detectors that do not accept filename yet.
                violations = detector.detect(code=code, language=language)
            all_violations.extend(violations)

        # Attempt auto-remediation
        remediated_code = code
        if all_violations:
            remediated_code = self.remediator.fix(
                code=code,
                violations=all_violations,
                language=language
            )

        # Build the response
        critical_count = sum(1 for v in all_violations if v["severity"] == "critical")
        high_count = sum(1 for v in all_violations if v["severity"] == "high")

        approved = len(all_violations) == 0

        if not all_violations:
            summary = "✅ No security violations found. Code is clear to ship."
        else:
            summary = (
                f"🚨 {len(all_violations)} violation(s) found "
                f"({critical_count} critical, {high_count} high). "
                f"Auto-fix has been applied — review before accepting."
            )

        return {
            "approved": approved,
            "filename": filename,
            "language": language,
            "violations": all_violations,
            "remediated_code": remediated_code,
            "summary": summary,
            "stats": {
                "total": len(all_violations),
                "critical": critical_count,
                "high": high_count,
            }
        }
