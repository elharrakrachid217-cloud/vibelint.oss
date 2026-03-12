# VibeLint Security Coverage Analysis

This document describes what VibeLint currently does in the codebase today.
It is implementation-based (from `server.py`, `core/scanner.py`, and active detectors), not estimated percentages.

---

## 1) Actual Scan Pipeline

VibeLint exposes one MCP tool: `security_check`.

For each call, the server:
1. Accepts `code`, `filename`, and `language`.
2. Runs `SecurityScanner.scan(...)`.
3. Returns a JSON result with:
   - `approved` (`true` when no violations)
   - `violations` (all findings)
   - `remediated_code` (auto-fixed or annotated output)
   - `summary`
   - `stats` (`total`, `critical`, `high`)

### Detectors currently executed (in order)
1. `SecretsDetector`
2. `AuthDetector`
3. `InjectionDetector`
4. `MissingAuthDetector`
5. `RateLimitingDetector`
6. `CorsDetector`
7. `FrameworkMisconfigDetector`
8. `SemgrepDetector` (optional at runtime if Semgrep is installed)
9. `PromptInjectionDetector`
10. `LLMOutputExecutionDetector`
11. `DependencyDetector`

---

## 2) Coverage by Detector (What is Actually Implemented)

### 2.1 SecretsDetector

Detects hard-coded secrets via two mechanisms:
- `detect-secrets` integration (if installed)
- built-in regex fallback/supplement

Built-in patterns include:
- Generic API/secret/token assignments
- OpenAI and Anthropic key formats
- AWS access key IDs and secret access keys
- DB URLs containing embedded credentials
- Hard-coded password assignments
- Stripe key formats
- env-var fallback patterns that embed a literal secret value
- hard-coded NextAuth secret and URL settings
- hard-coded `NEXT_PUBLIC_*` values

Notes:
- Comment lines are skipped.
- Placeholder tokens (`YOUR_KEY_HERE`) are ignored.
- `detect-secrets` failures degrade gracefully to regex scanning.

### 2.2 AuthDetector

Flags insecure authentication patterns, including:
- Weak password hashing primitives
- Possible plain-text password comparisons
- JWT decode flows with signature verification disabled
- JWT algorithm-none flows
- Hard-coded admin credentials
- SQL auth query injection-shaped patterns
- Token storage in browser local storage
- Credentials in URL query params in request calls
- NextAuth production debug enabled

### 2.3 InjectionDetector

Regex-based detection for:
- SQL injection (string interpolation/formatting/concatenation styles)
- NoSQL injection anti-patterns (raw request object usage in Mongo queries, variable-driven operator usage, parsed-JSON query objects)
- XSS-oriented patterns (dynamic HTML assignment, dynamic evaluation, unsafe document write, unsanitized HTML rendering)
- Prototype pollution pattern (dynamic user-controlled object keys)
- Command injection (`os.system`, subprocess with shell mode enabled)
- Path traversal risk (`open(...)` with dynamic/user-controlled path)

### 2.4 MissingAuthDetector

Finds route definitions across multiple frameworks and checks for nearby auth evidence.

Framework route patterns include:
- Flask/FastAPI decorators
- Django DRF markers
- Express-style route methods
- Next.js route handler exports
- Spring mapping annotations
- Go handler registrations

Behavior:
- Skips safe/public paths (health, docs, static assets, etc.)
- Scans a local window around each route for auth signals
- Emits:
  - `missing_auth` when no auth signal is found
  - `missing_authorization` for sensitive routes with auth but no role/permission signal

### 2.5 RateLimitingDetector

Detects missing or weak throttling controls.

What it checks:
- Route-level and global rate-limit evidence across major frameworks
- Sensitive routes (login/token/reset/otp style endpoints)
- Write/API routes likely to need protection
- Weak/no-op limiter configs (for example zero or infinite limits)

Findings emitted:
- `missing_rate_limiting`
- `weak_rate_limit_config`

### 2.6 CorsDetector

Detects wildcard/overly permissive CORS configurations, including:
- Express wildcard CORS patterns
- FastAPI wildcard origin allow-list
- Django all-origins settings and wildcard origin lists
- Spring wildcard origin settings
- Go wildcard origin settings
- ASP.NET any-origin settings
- Manual wildcard `Access-Control-Allow-Origin` headers

### 2.7 FrameworkMisconfigDetector

Currently focused on Django/Flask production-risk settings:
- Django debug enabled
- Django wildcard allowed hosts
- Django insecure cookie secure flags
- Flask run/debug enabled in production contexts

Severity may escalate to `critical` for debug-mode findings in production-like filenames (for example `settings.py`, `production.py`, `prod.py`, `config.py`, `wsgi.py`).

### 2.8 SemgrepDetector (Optional)

Runs Semgrep (`p/security-audit`) against a temp file and maps findings into VibeLint violation format.

Important runtime behavior:
- If `semgrep` is not installed, this detector returns no findings.
- If Semgrep errors or times out, it returns no findings.
- If present, Semgrep expands coverage beyond built-in regex rules.

### 2.9 PromptInjectionDetector

Two-phase detector:
- Regex phase for prompt-injection keywords, taint sources, AI sink patterns, MCP escalation shapes, and encoding/obfuscation indicators.
- Python AST phase for multi-line taint propagation from external/user input into LLM calls without sanitization.

Representative findings:
- `prompt_injection_keyword`
- `prompt_injection_direct`
- `prompt_injection_indirect`
- `prompt_injection_missing_sanitization`
- `prompt_injection_mcp_escalation`

### 2.10 LLMOutputExecutionDetector

Flags direct flow from LLM response-shaped fields to dangerous execution sinks without validation/sandbox markers.

Sinks include Python and JS/TS execution primitives such as:
- dynamic code execution functions
- shell/process execution functions

Finding type:
- `llm_output_execution`

### 2.11 DependencyDetector

Software composition analysis for dependency manifests identified by filename.

Supported manifests include:
- Python: `requirements*.txt`, `Pipfile`, `pyproject.toml`
- JS: `package.json`, `package-lock.json`
- Go: `go.mod`
- Ruby: `Gemfile`
- Rust: `Cargo.toml`
- PHP: `composer.json`
- Java/Kotlin: `pom.xml`, `build.gradle`, `build.gradle.kts`
- .NET: `*.csproj`

Behavior:
- Queries OSV first (with in-memory cache).
- Falls back to static known-vulnerability signatures when OSV is unavailable or returns no match.
- Emits `vulnerable_dependency` with package/version/CVE/fixed-version metadata.

---

## 3) Remediation Behavior (Current)

`remediated_code` is always returned when violations exist, but remediation is conservative.

Automatic rewrites currently implemented:
- Hard-coded secret replacement with environment-variable references (language-aware templates)
- Vulnerable dependency version bump patterns
- Prompt-injection helper setup and wrapping in specific cases

For many other finding types, VibeLint adds explicit warning/fix comments above offending lines rather than performing deep semantic rewrites.

---

## 4) Runtime Context-Firewall Modules (Present in Repo)

The repository includes runtime prompt-defense modules under `core/runtime/`:
- `ContextFirewall`
- `ActionPolicyEngine`
- `AuditLogger`
- semantic-judge and replay harness

These provide decisioning modes such as `ALLOW`, `ALLOW_NEUTRALIZED`, `SUMMARIZE_ONLY`, `REQUIRE_APPROVAL`, and `BLOCK` for untrusted context handling.

Important scope note:
- These runtime modules are implementation artifacts in the repo, but they are separate from the core `security_check -> SecurityScanner.scan()` detector pipeline described above.

---

## 5) Hard Limits / Non-Goals in Current Implementation

- Core detector logic is primarily regex-based, with Python AST augmentation in prompt-injection analysis.
- Presence/quality of Semgrep and detect-secrets findings depends on local runtime availability.
- Dependency SCA only activates for recognized manifest filenames.
- Architecture-level issues not expressed in scanned code/manifests may not be detected.

---

## 6) Bottom Line

VibeLint today is a multi-detector pre-write security gate centered on:
- secrets
- auth mistakes and missing auth controls
- injection families (SQL/NoSQL/XSS/command/path)
- CORS and framework misconfiguration
- rate-limiting gaps
- prompt-injection and LLM-output execution risks
- dependency vulnerabilities from manifests

This description reflects the current implementation behavior in the repository, not estimated percentage coverage claims.
