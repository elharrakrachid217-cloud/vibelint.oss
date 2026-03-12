"""
core/remediator.py
==================
Takes code with known violations and applies automatic fixes.

This is VibeLint's superpower — we don't just flag problems,
we hand the developer a fixed version they can accept with one click.

Current auto-fixes:
- Replace hard-coded secrets with os.environ.get() calls
- Add .env template comments
- Flag auth issues with inline TODO comments (full AST rewrite is v2)

NOTE: The remediator is intentionally conservative.
We only auto-fix things we're 100% sure about.
For complex patterns (auth rewrites), we add a clear TODO comment
and let the developer make the change with guidance.
"""

import re

_HASH_COMMENT_LANGS = {"python", "ruby", "bash", "shell", "r", "elixir", "yaml", "terraform", "dockerfile"}
_SLASH_COMMENT_LANGS = {
    "javascript", "typescript", "java", "go", "php", "c", "cpp",
    "csharp", "rust", "kotlin", "swift", "scala", "lua",
}


def _comment_prefix(language: str) -> str:
    if language in _HASH_COMMENT_LANGS:
        return "#"
    if language in _SLASH_COMMENT_LANGS:
        return "//"
    if language == "html":
        return "<!--"
    return "#"


def _comment_suffix(language: str) -> str:
    if language == "html":
        return " -->"
    return ""


class Remediator:

    def fix(self, code: str, violations: list[dict], language: str) -> str:
        """
        Apply fixes for all violations and return the remediated code.
        """
        remediated = code

        for violation in violations:
            if violation["type"] == "hard_coded_secret":
                remediated = self._fix_secret(remediated, violation, language)
            elif violation["type"] == "insecure_auth":
                remediated = self._add_warning_comment(remediated, violation, language)
            elif violation["type"] == "injection_risk":
                remediated = self._add_warning_comment(remediated, violation, language)
            elif violation["type"] in {"missing_auth", "missing_authorization"}:
                remediated = self._add_warning_comment(remediated, violation, language)
            elif violation["type"] in {"missing_rate_limiting", "weak_rate_limit_config"}:
                remediated = self._add_warning_comment(remediated, violation, language)
            elif violation["type"] == "cors_misconfiguration":
                remediated = self._add_warning_comment(remediated, violation, language)
            elif violation["type"] == "framework_misconfiguration":
                remediated = self._add_warning_comment(remediated, violation, language)
            elif violation["type"] == "semgrep_finding":
                remediated = self._add_warning_comment(remediated, violation, language)
            elif violation["type"] == "vulnerable_dependency":
                remediated = self._fix_dependency(remediated, violation)
            elif violation["type"] in {
                "prompt_injection_direct",
                "prompt_injection_indirect",
                "prompt_injection_missing_sanitization",
            }:
                remediated = self._fix_prompt_injection(remediated, violation, language)
            elif str(violation["type"]).startswith("prompt_injection"):
                remediated = self._add_warning_comment(remediated, violation, language)
            elif str(violation["type"]).startswith("llm_output_execution"):
                remediated = self._add_warning_comment(remediated, violation, language)

        return remediated

    def _fix_secret(self, code: str, violation: dict, language: str) -> str:
        """
        Replace hard-coded secrets with environment variable references.
        This is the one fix we can do automatically with high confidence.
        """
        line_to_fix = violation.get("offending_line", "")
        if not line_to_fix:
            return code

        lines = code.split('\n')
        fixed_lines = []

        for line in lines:
            if line.strip() == line_to_fix:
                fixed_line = self._replace_with_env_var(line, language)
                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)

        return '\n'.join(fixed_lines)

    _ENV_VAR_TEMPLATES: dict[str, str] = {
        "python":     '{indent}{var} = os.environ.get("{var}")  # secret moved to .env',
        "javascript": '{indent}const {var} = process.env.{var};  // secret moved to .env',
        "typescript": '{indent}const {var} = process.env.{var};  // secret moved to .env',
        "java":       '{indent}String {var} = System.getenv("{var}");  // secret moved to .env',
        "go":         '{indent}{var} := os.Getenv("{var}")  // secret moved to .env',
        "ruby":       "{indent}{var} = ENV['{var}']  # secret moved to .env",
        "php":        "{indent}${var} = getenv('{var}');  // secret moved to .env",
        "rust":       '{indent}let {var} = std::env::var("{var}").expect("{var} not set");  // secret moved to .env',
        "csharp":     '{indent}var {var} = Environment.GetEnvironmentVariable("{var}");  // secret moved to .env',
        "kotlin":     '{indent}val {var} = System.getenv("{var}")  // secret moved to .env',
        "swift":      '{indent}let {var} = ProcessInfo.processInfo.environment["{var}"]  // secret moved to .env',
        "scala":      '{indent}val {var} = sys.env.getOrElse("{var}", "")  // secret moved to .env',
    }

    def _replace_with_env_var(self, line: str, language: str) -> str:
        """
        Transform:   API_KEY = "sk-abc123..."
        Into:        API_KEY = os.environ.get("API_KEY")  # 🔍 VibeLint: secret moved to .env
        """
        cp = _comment_prefix(language)
        cs = _comment_suffix(language)
        match = re.search(r'(\b\w+)\s*=\s*["\'].*["\']', line)
        if not match:
            indent = re.match(r'(\s*)', line).group(1) if line.strip() else ""
            return (
                f"{indent}{cp} VIBELINT: Hard-coded secret removed. "
                f"Load from environment variable.{cs}"
            )

        indent = re.match(r'(\s*)', line).group(1) if line.strip() else ""
        var_name = match.group(1).upper()

        template = self._ENV_VAR_TEMPLATES.get(language)
        if template:
            return template.format(indent=indent, var=var_name)

        return f"{indent}{cp} VIBELINT: Replace with env var for {var_name}{cs}"

    def _fix_dependency(self, code: str, violation: dict) -> str:
        """Bump vulnerable dependency versions in a conservative way."""
        metadata = violation.get("metadata") or {}
        package = str(metadata.get("package") or "")
        old_ver = str(metadata.get("version") or "")
        fixed_ver = str(metadata.get("fixed_version") or "")
        if not package or not old_ver or not fixed_ver:
            return code

        line_match = (violation.get("offending_line") or "").strip()
        out_lines: list[str] = []
        changed = False

        for line in code.split("\n"):
            candidate = line
            if line_match and line.strip() == line_match and not changed:
                candidate = self._replace_dep_tokens(candidate, package, old_ver, fixed_ver)
                changed = candidate != line
                out_lines.append(candidate)
                continue

            if not changed:
                candidate = self._replace_dep_tokens(candidate, package, old_ver, fixed_ver)
                changed = candidate != line

            out_lines.append(candidate)

        return "\n".join(out_lines)

    def _replace_dep_tokens(self, line: str, package: str, old_ver: str, fixed_ver: str) -> str:
        candidate = line
        candidate = candidate.replace(f"{package}=={old_ver}", f"{package}=={fixed_ver}")
        candidate = candidate.replace(f"{package}>={old_ver}", f"{package}>={fixed_ver}")
        candidate = candidate.replace(f"{package}={old_ver}", f"{package}={fixed_ver}")
        candidate = candidate.replace(f'"{package}": "^{old_ver}"', f'"{package}": "^{fixed_ver}"')
        candidate = candidate.replace(f'"{package}": "~{old_ver}"', f'"{package}": "~{fixed_ver}"')
        candidate = candidate.replace(f'"{package}": "{old_ver}"', f'"{package}": "{fixed_ver}"')
        candidate = candidate.replace(f"'{package}': '^{old_ver}'", f"'{package}': '^{fixed_ver}'")
        candidate = candidate.replace(f"'{package}': '~{old_ver}'", f"'{package}': '~{fixed_ver}'")
        candidate = candidate.replace(f"'{package}': '{old_ver}'", f"'{package}': '{fixed_ver}'")
        candidate = candidate.replace(f"{package}:{old_ver}", f"{package}:{fixed_ver}")
        candidate = candidate.replace(f'Version="{old_ver}"', f'Version="{fixed_ver}"')
        return candidate

    def _fix_prompt_injection(self, code: str, violation: dict, language: str) -> str:
        """
        Conservative auto-remediation for prompt injection:
        - inject a sanitizer helper when missing
        - wrap prompt/content expressions on the violating line
        - add warning comments for reviewer context
        """
        line_to_fix = violation.get("offending_line", "")
        if not line_to_fix:
            return code

        wrapper = "sanitize_prompt"
        if violation.get("type") == "prompt_injection_indirect":
            wrapper = "sanitize_external_content"

        remediated = self._ensure_prompt_sanitizer_helper(code, language, wrapper)
        lines = remediated.split("\n")
        fixed_lines = []
        comment_target = line_to_fix

        for line in lines:
            if line.strip() == line_to_fix:
                wrapped = self._wrap_ai_content_expression(line, wrapper)
                fixed_lines.append(wrapped)
                comment_target = wrapped.strip()
            else:
                fixed_lines.append(line)

        remediated = "\n".join(fixed_lines)
        return self._add_warning_comment(remediated, violation, language, target_line=comment_target)

    def _ensure_prompt_sanitizer_helper(self, code: str, language: str, wrapper: str) -> str:
        if wrapper in code:
            return code

        if language == "python":
            helper = (
                f"def {wrapper}(text):\n"
                "    if text is None:\n"
                "        return ''\n"
                "    value = str(text)\n"
                "    value = re.sub(r'(?i)(ignore\\s+previous\\s+instructions|disregard\\s+your\\s+instructions|forget\\s+everything\\s+above)', '', value)\n"
                "    return value.strip()\n\n"
            )
            if "import re" not in code:
                return "import re\n\n" + helper + code
            return helper + code

        if language in {"javascript", "typescript"}:
            helper = (
                f"const {wrapper} = (text) => {{\n"
                "  if (text == null) return '';\n"
                "  return String(text)\n"
                "    .replace(/(ignore\\s+previous\\s+instructions|disregard\\s+your\\s+instructions|forget\\s+everything\\s+above)/gi, '')\n"
                "    .trim();\n"
                "};\n\n"
            )
            return helper + code

        return code

    def _wrap_ai_content_expression(self, line: str, wrapper: str) -> str:
        line = re.sub(
            r"('content'\s*:\s*)([^,}\]]+)",
            lambda m: m.group(0) if wrapper in m.group(2) else f"{m.group(1)}{wrapper}({m.group(2).strip()})",
            line,
        )
        line = re.sub(
            r'("content"\s*:\s*)([^,}\]]+)',
            lambda m: m.group(0) if wrapper in m.group(2) else f"{m.group(1)}{wrapper}({m.group(2).strip()})",
            line,
        )
        line = re.sub(
            r"(\bprompt\s*=\s*)([^,\)]+)",
            lambda m: m.group(0) if wrapper in m.group(2) else f"{m.group(1)}{wrapper}({m.group(2).strip()})",
            line,
        )
        return line

    def _add_warning_comment(self, code: str, violation: dict, language: str, target_line: str | None = None) -> str:
        """
        For complex violations (auth, injection), inject a clear warning comment
        above the offending line with the fix hint.
        This is safer than attempting an automatic rewrite.
        """
        line_to_match = target_line if target_line is not None else violation.get("offending_line", "")
        if not line_to_match:
            return code

        fix_hint = violation.get("fix_hint", "Review this line for security issues.")
        description = violation.get("description", "Security issue detected.")

        cp = _comment_prefix(language)
        cs = _comment_suffix(language)

        lines = code.split('\n')
        fixed_lines = []

        for line in lines:
            if line.strip() == line_to_match:
                indent = re.match(r'(\s*)', line).group(1)
                fixed_lines.append(
                    f'{indent}{cp} VIBELINT [{violation["severity"].upper()}]: {description}{cs}'
                )
                fixed_lines.append(f'{indent}{cp} FIX: {fix_hint}{cs}')
                fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        return '\n'.join(fixed_lines)