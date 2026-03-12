"""
core/detectors/secrets.py
=========================
Detects hard-coded secrets in AI-generated code.

Primary scanner: Yelp's detect-secrets library (30+ built-in plugins
for high-entropy strings, vendor keys, private keys, etc.).
Fallback: hand-tuned regex patterns for vendor-specific keys and
patterns common in vibe-coded projects.

Patterns we catch:
- API keys (OpenAI, Anthropic, AWS, Stripe, etc.)
- Database connection strings with credentials
- Hard-coded passwords in variable assignments
- JWT secrets and OAuth tokens
- High-entropy strings via detect-secrets entropy plugins
"""

import logging
import os
import re
import tempfile

from core.detectors.base import BaseDetector

try:
    from detect_secrets import SecretsCollection
    from detect_secrets.settings import default_settings
    _HAS_DETECT_SECRETS = True
except ImportError:
    _HAS_DETECT_SECRETS = False

logger = logging.getLogger(__name__)


class SecretsDetector(BaseDetector):

    # Regex fallback / supplement patterns.
    # Each tuple: (pattern, description, severity)
    SECRET_PATTERNS = [
        # Generic high-entropy strings assigned to key-sounding variables
        (
            r'(?i)(api_key|apikey|api_secret|secret_key|private_key|access_token|auth_token|jwt_secret)\s*=\s*["\']([A-Za-z0-9+/\-_]{20,})["\']',
            "Hard-coded API key or secret token detected",
            "critical"
        ),
        # OpenAI / Anthropic keys (very common in vibe coding)
        (
            r'sk-[A-Za-z0-9]{20,}',
            "Hard-coded OpenAI API key detected (sk-...)",
            "critical"
        ),
        (
            r'sk-ant-[A-Za-z0-9\-]{20,}',
            "Hard-coded Anthropic API key detected",
            "critical"
        ),
        # AWS credentials
        (
            r'AKIA[0-9A-Z]{16}',
            "Hard-coded AWS Access Key ID detected",
            "critical"
        ),
        (
            r'(?i)aws_secret_access_key\s*=\s*["\'][A-Za-z0-9+/]{40}["\']',
            "Hard-coded AWS Secret Access Key detected",
            "critical"
        ),
        # Database URLs with credentials embedded
        (
            r'(?i)(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@',
            "Database connection string contains hard-coded credentials",
            "critical"
        ),
        # Hard-coded passwords
        (
            r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{6,}["\']',
            "Hard-coded password detected in source code",
            "high"
        ),
        # Stripe keys
        (
            r'(?i)(sk_live|sk_test|pk_live|pk_test)_[A-Za-z0-9]{24,}',
            "Hard-coded Stripe API key detected",
            "critical"
        ),
        # JS/TS: process.env fallback with hardcoded secret (defeats env vars)
        (
            r'(?i)process\.env\.\w+\s*\|\|\s*["\'][^"\']{8,}["\']',
            "Hardcoded fallback for process.env defeats the purpose of environment variables",
            "high"
        ),
        # Next.js: NEXTAUTH_SECRET or NEXTAUTH_URL hardcoded
        (
            r'(?i)(NEXTAUTH_SECRET|NEXTAUTH_URL)\s*[:=]\s*["\'][^"\']{8,}["\']',
            "Hard-coded Next.js auth secret detected. Move to .env.local",
            "critical"
        ),
        # Next.js: NEXT_PUBLIC_ variables hardcoded instead of .env.local
        (
            r'(?i)NEXT_PUBLIC_\w+\s*[:=]\s*["\'][^"\']{8,}["\']',
            "NEXT_PUBLIC_ variable hardcoded instead of loading from .env.local",
            "high"
        ),
    ]

    def detect(self, code: str, language: str) -> list[dict]:
        violations: list[dict] = []
        seen_lines: set[int] = set()

        if _HAS_DETECT_SECRETS:
            for v in self._scan_with_detect_secrets(code, language):
                seen_lines.add(v["line"])
                violations.append(v)

        for v in self._scan_with_regex(code, language):
            if v["line"] not in seen_lines:
                violations.append(v)
                seen_lines.add(v["line"])

        return violations

    # ------------------------------------------------------------------ #
    #  detect-secrets integration                                         #
    # ------------------------------------------------------------------ #

    _PLACEHOLDER_TOKENS = {"YOUR_KEY_HERE", "your_key_here"}

    def _scan_with_detect_secrets(self, code: str, language: str) -> list[dict]:
        """Write *code* to a temp file and scan it with detect-secrets."""
        ext = {
            "python": ".py", "javascript": ".js", "typescript": ".ts",
            "java": ".java", "go": ".go", "ruby": ".rb", "php": ".php",
            "c": ".c", "cpp": ".cpp", "csharp": ".cs", "rust": ".rs",
            "kotlin": ".kt", "swift": ".swift", "scala": ".scala",
            "bash": ".sh", "shell": ".sh", "lua": ".lua", "r": ".r",
            "elixir": ".ex", "terraform": ".tf", "dockerfile": ".dockerfile",
            "html": ".html", "json": ".json", "yaml": ".yaml",
        }.get(language, ".txt")
        tmp_path: str | None = None
        results: list[dict] = []
        seen_lines: set[int] = set()

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=ext, delete=False, encoding="utf-8"
            ) as fh:
                fh.write(code)
                tmp_path = fh.name

            secrets = SecretsCollection()
            with default_settings():
                secrets.scan_file(tmp_path)

            lines = code.split("\n")
            for _fname, secret_set in secrets.data.items():
                for secret in secret_set:
                    line_num = secret.line_number
                    if line_num in seen_lines:
                        continue
                    raw_line = lines[line_num - 1] if line_num <= len(lines) else ""
                    if any(tok in raw_line for tok in self._PLACEHOLDER_TOKENS):
                        continue
                    seen_lines.add(line_num)
                    results.append({
                        "type": "hard_coded_secret",
                        "severity": "critical",
                        "line": line_num,
                        "description": (
                            f"Secret detected by detect-secrets ({secret.type})"
                        ),
                        "offending_line": raw_line.strip(),
                        "fix_hint": self._get_fix_hint("", "", language),
                    })
        except Exception as exc:
            logger.debug(
                "detect-secrets scan failed, falling back to regex: %s", exc
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

        return results

    # ------------------------------------------------------------------ #
    #  Regex fallback                                                     #
    # ------------------------------------------------------------------ #

    def _scan_with_regex(self, code: str, language: str) -> list[dict]:
        """Run hand-tuned regex patterns over *code*."""
        violations: list[dict] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if "YOUR_KEY_HERE" in line or "your_key_here" in line:
                continue

            for pattern, description, severity in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    violations.append({
                        "type": "hard_coded_secret",
                        "severity": severity,
                        "line": line_num,
                        "description": description,
                        "offending_line": line.strip(),
                        "fix_hint": self._get_fix_hint(pattern, line, language),
                    })
                    break

        return violations

    _SECRET_FIX_HINTS: dict[str, str] = {
        "python": (
            "Remove this hard-coded value. "
            "Add it to a .env file and load it with: "
            "import os; value = os.environ.get('YOUR_VAR_NAME'). "
            "Make sure .env is in your .gitignore."
        ),
        "javascript": (
            "Remove this hard-coded value. "
            "Add it to a .env file and access it with: "
            "process.env.YOUR_VAR_NAME. "
            "Install dotenv: npm install dotenv, then add require('dotenv').config() at the top."
        ),
        "typescript": (
            "Remove this hard-coded value. "
            "Add it to a .env file and access it with: "
            "process.env.YOUR_VAR_NAME. "
            "Install dotenv: npm install dotenv, then add require('dotenv').config() at the top."
        ),
        "java": (
            "Remove this hard-coded value. "
            "Load it from an environment variable: System.getenv(\"YOUR_VAR_NAME\"), "
            "or use a secrets manager. Never commit credentials to source control."
        ),
        "go": (
            "Remove this hard-coded value. "
            "Load it with os.Getenv(\"YOUR_VAR_NAME\") or use a library like godotenv. "
            "Never commit credentials to source control."
        ),
        "ruby": (
            "Remove this hard-coded value. "
            "Load it with ENV['YOUR_VAR_NAME'] or use the dotenv gem. "
            "Never commit credentials to source control."
        ),
        "php": (
            "Remove this hard-coded value. "
            "Load it with getenv('YOUR_VAR_NAME') or $_ENV['YOUR_VAR_NAME']. "
            "Use vlucas/phpdotenv for .env support. Never commit credentials to source control."
        ),
        "rust": (
            "Remove this hard-coded value. "
            "Load it with std::env::var(\"YOUR_VAR_NAME\") or use the dotenvy crate. "
            "Never commit credentials to source control."
        ),
        "csharp": (
            "Remove this hard-coded value. "
            "Load it with Environment.GetEnvironmentVariable(\"YOUR_VAR_NAME\") "
            "or use IConfiguration with user-secrets. Never commit credentials to source control."
        ),
        "kotlin": (
            "Remove this hard-coded value. "
            "Load it with System.getenv(\"YOUR_VAR_NAME\") or use a secrets manager. "
            "Never commit credentials to source control."
        ),
        "swift": (
            "Remove this hard-coded value. "
            "Load it from ProcessInfo.processInfo.environment[\"YOUR_VAR_NAME\"] "
            "or use a configuration file excluded from version control."
        ),
    }

    def _get_fix_hint(self, pattern: str, line: str, language: str) -> str:
        """Return a specific, actionable fix instruction for the violation."""
        hint = self._SECRET_FIX_HINTS.get(language)
        if hint:
            return hint
        return "Move this value to an environment variable and never commit it to source control."
