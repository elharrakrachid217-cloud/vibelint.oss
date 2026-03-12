"""
core/detectors/semgrep.py
=========================
Data-flow analysis via Semgrep CE (Community Edition).

Runs Semgrep as a subprocess with the p/security-audit ruleset
against a temp file and converts JSON findings into VibeLint's
standard violation format.

Degrades gracefully: if semgrep is not installed or the scan
fails for any reason, detect() returns an empty list.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

_semgrep_bin: str | None = shutil.which("semgrep")

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "ERROR":    "high",
    "HIGH":     "high",
    "WARNING":  "medium",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "low",
}

_EXT_MAP: dict[str, str] = {
    "python":     ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java":       ".java",
    "go":         ".go",
    "ruby":       ".rb",
    "php":        ".php",
    "c":          ".c",
    "cpp":        ".cpp",
    "csharp":     ".cs",
    "rust":       ".rs",
    "kotlin":     ".kt",
    "swift":      ".swift",
    "scala":      ".scala",
    "bash":       ".sh",
    "shell":      ".sh",
    "lua":        ".lua",
    "r":          ".r",
    "elixir":     ".ex",
    "terraform":  ".tf",
    "dockerfile": ".dockerfile",
    "html":       ".html",
    "json":       ".json",
    "yaml":       ".yaml",
}

_TIMEOUT_SECONDS = 60
_DEFAULT_RULESET = "p/security-audit"


class SemgrepDetector(BaseDetector):
    """Wraps Semgrep CE as a VibeLint detector for data-flow analysis."""

    _warned_missing = False

    def __init__(self, ruleset: str | list[str] = _DEFAULT_RULESET):
        if isinstance(ruleset, str):
            self._configs = [ruleset]
        else:
            self._configs = list(ruleset)

        if isinstance(ruleset, str) and ruleset == _DEFAULT_RULESET:
            local_nosql = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep" / "nosql"
            if local_nosql.exists() and local_nosql.is_dir():
                self._configs.append(str(local_nosql))

    def detect(self, code: str, language: str) -> list[dict]:
        if not _semgrep_bin:
            if not SemgrepDetector._warned_missing:
                logger.warning(
                    "semgrep not found on PATH — skipping data-flow analysis. "
                    "Install with: pip install semgrep"
                )
                SemgrepDetector._warned_missing = True
            return []

        return self._run_semgrep(code, language)

    def _run_semgrep(self, code: str, language: str) -> list[dict]:
        ext = _EXT_MAP.get(language, ".txt")
        tmp_path: str | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=ext, delete=False, encoding="utf-8"
            ) as fh:
                fh.write(code)
                tmp_path = fh.name

            cmd = [
                _semgrep_bin,
                "scan",
                "--json",
                "--quiet",
                "--no-git-ignore",
            ]
            for config in self._configs:
                cmd.extend(["--config", config])
            cmd.append(tmp_path)

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )

            # semgrep exits 0 = clean, 1 = findings present, >=2 = error
            if proc.returncode >= 2:
                logger.debug(
                    "semgrep exited with code %d: %s",
                    proc.returncode,
                    proc.stderr[:500],
                )
                return []

            return self._parse_output(proc.stdout, code)

        except subprocess.TimeoutExpired:
            logger.debug("semgrep timed out after %ds", _TIMEOUT_SECONDS)
            return []
        except Exception as exc:
            logger.debug("semgrep scan failed: %s", exc)
            return []
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @staticmethod
    def _parse_output(raw_json: str, code: str) -> list[dict]:
        """Convert semgrep JSON output into VibeLint violations."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            logger.debug("Failed to parse semgrep JSON: %s", exc)
            return []

        lines = code.split("\n")
        violations: list[dict] = []
        seen_lines: set[int] = set()

        for match in data.get("results", []):
            line_num = match.get("start", {}).get("line", 0)
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)

            extra = match.get("extra", {})
            severity_raw = extra.get("severity", "WARNING")
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            check_id = match.get("check_id", "unknown")
            message = extra.get("message", "Security issue detected by Semgrep")

            offending = (
                lines[line_num - 1].strip()
                if 0 < line_num <= len(lines)
                else extra.get("lines", "").strip()
            )

            fix_hint = extra.get("fix", "")
            if not fix_hint:
                fix_hint = (
                    f"Semgrep rule {check_id}: {message}. "
                    "Review and apply the recommended fix."
                )

            violations.append({
                "type": "semgrep_finding",
                "severity": severity,
                "line": line_num,
                "description": f"[Semgrep] {message}",
                "offending_line": offending,
                "fix_hint": fix_hint,
            })

        return violations
