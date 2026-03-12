# VibeLint — Complete Documentation

**Landing Page:** [www.vibelint.com](https://www.vibelint.com)  
**GitHub Repository:** [https://github.com/elharrakrachid217-cloud/vibelint](https://github.com/elharrakrachid217-cloud/vibelint)

---

## Table of Contents

1. [What is VibeLint?](#what-is-vibelint)
2. [What Does VibeLint Do?](#what-does-vibelint-do)
3. [Who Is VibeLint For?](#who-is-vibelint-for)
4. [Technology Stack](#technology-stack)
5. [Security Risks Detected (Complete List)](#security-risks-detected-complete-list)
6. [Setup Guide](#setup-guide)

---

## What is VibeLint?

**VibeLint** is a **pre-write security gate** that catches vulnerabilities in AI-generated code **before** it is written to disk. It runs locally, automatically, and for free as an MCP (Model Context Protocol) server integrated with AI-powered IDEs such as Cursor, Windsurf, and Claude Desktop.

VibeLint acts as a mandatory checkpoint: whenever an AI agent generates code, the IDE calls VibeLint's `security_check` tool first. The code is scanned for security issues; if violations are found, VibeLint returns auto-remediated code. The developer (or AI) then uses the fixed version instead of the original. This creates a **fail-closed** security model instead of best-effort.

---

## What Does VibeLint Do?

- **Scans** every code block before it is written to disk
- **Detects** hard-coded secrets, insecure auth, injection risks, prompt injection, and more
- **Returns** pass/fail status, violation details with severity, and **auto-fixed code**
- **Integrates** via MCP with Cursor, Windsurf, Claude Desktop, and other MCP-compatible tools
- **Enforces** fail-closed behavior: if VibeLint is unavailable, writes are blocked
- **Logs** scan results to an SQLite-backed audit log
- **Supports** a git pre-commit hook to block commits with violations
- **Runs** as an optional background service that auto-starts at login

---

## Who Is VibeLint For?

- **Developers** who use AI coding assistants (Cursor, Windsurf, Claude Code, etc.) and want to prevent insecure code from reaching their codebase
- **Teams** adopting AI-assisted development who need a security gate without slowing down velocity
- **Security-conscious engineers** who want to catch common AI-generated vulnerabilities (secrets, weak auth, injection) before code review
- **Anyone** building applications with AI-generated code who values local, free, and automatic security scanning

---

## Technology Stack


| Component           | Technology                                        |
| ------------------- | ------------------------------------------------- |
| **Language**        | Python 3.10+                                      |
| **MCP Protocol**    | Anthropic MCP Server (`mcp>=1.0.0`)               |
| **Web Framework**   | FastAPI (for future REST API / dashboard)         |
| **ASGI Server**     | Uvicorn                                           |
| **Secret Scanning** | Yelp's `detect-secrets` (primary), regex fallback |
| **Static Analysis** | Semgrep CE (optional, `p/security-audit` ruleset) |
| **Dependency SCA**  | OSV API + static fallback (`known_vulns`)         |
| **Version Parsing** | `packaging`                                       |
| **Testing**         | pytest, pytest-asyncio                            |
| **Environment**     | python-dotenv                                     |


---

## Security Risks Detected (Complete List)

VibeLint runs **11 detectors** in sequence. Each risk category is described below with details on **what patterns are caught** and **how VibeLint catches them**.

---

### 1. Hard-Coded Secrets (SecretsDetector)


| Risk                                    | Severity   | How VibeLint Catches It                                                                                                                                        |
| --------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Generic API keys / tokens**           | `critical` | Regex: `api_key`, `apikey`, `api_secret`, `secret_key`, `private_key`, `access_token`, `auth_token`, `jwt_secret` assigned to high-entropy strings (20+ chars) |
| **OpenAI API keys**                     | `critical` | Regex: `sk-[A-Za-z0-9]{20,}`                                                                                                                                   |
| **Anthropic API keys**                  | `critical` | Regex: `sk-ant-[A-Za-z0-9\-]{20,}`                                                                                                                             |
| **AWS Access Key IDs**                  | `critical` | Regex: `AKIA[0-9A-Z]{16}`                                                                                                                                      |
| **AWS Secret Access Keys**              | `critical` | Regex: `aws_secret_access_key = ["'][40-char]`                                                                                                                 |
| **Database URLs with credentials**      | `critical` | Regex: `postgres://`, `mysql://`, `mongodb://`, `redis://` with embedded credentials                                                                           |
| **Hard-coded passwords**                | `high`     | Regex: `password`, `passwd`, `pwd` assigned to string literals                                                                                                 |
| **Stripe keys**                         | `critical` | Regex: `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_`                                                                                                          |
| **process.env fallback bypass (JS/TS)** | `high`     | Regex: `process.env.KEY || "fallback"` — defeats env vars                                                                                                      |
| **NextAuth hardcoded secrets**          | `critical` | Regex: `NEXTAUTH_SECRET` or `NEXTAUTH_URL` hardcoded                                                                                                           |
| *NEXT_PUBLIC_ hardcoded**               | `high`     | Regex: `NEXT_PUBLIC_`* variables hardcoded inline                                                                                                              |
| **High-entropy strings (generic)**      | `critical` | Yelp's `detect-secrets` (30+ plugins) when installed                                                                                                           |


**Detection:** Primary: `detect-secrets` library. Fallback: hand-tuned regex. Comment lines and placeholders like `YOUR_KEY_HERE` are skipped.

---

### 2. Insecure Authentication (AuthDetector)


| Risk                                  | Severity   | How VibeLint Catches It                                                       |
| ------------------------------------- | ---------- | ----------------------------------------------------------------------------- |
| **MD5/SHA1 for passwords**            | `critical` | Regex: `hashlib.md5`, `hashlib.sha1`, `md5(`, `sha1(`                         |
| **Plain-text password comparison**    | `critical` | Regex: `password ==` or `== password`                                         |
| **JWT decode without verification**   | `critical` | Regex: `jwt.decode` with `verify=False`                                       |
| **JWT algorithm 'none'**              | `critical` | Regex: `jwt.decode` with `algorithms=['none']`                                |
| **Hard-coded admin credentials**      | `critical` | Regex: `admin.*password` or `password.*admin` assignment                      |
| **SQL auth query injection**          | `critical` | Regex: `SELECT.*FROM.*users.*WHERE.*password` with string interpolation       |
| **localStorage JWT storage (JS/TS)**  | `high`     | Regex: `localStorage.setItem/getItem` with `token`, `jwt`, `auth_token`, etc. |
| **Credentials in URL params (fetch)** | `high`     | Regex: `fetch(.*[&](token                                                     |
| **NextAuth debug mode**               | `high`     | Regex: `NextAuth(.*debug : true`                                              |


**Detection:** Regex-based pattern matching. Comment lines skipped.

---

### 3. Injection Risks (InjectionDetector)

#### SQL Injection


| Risk                             | Severity   | How VibeLint Catches It                                      |
| -------------------------------- | ---------- | ------------------------------------------------------------ |
| **f-string SQL**                 | `critical` | Regex: `execute(`, `query(`, `cursor.execute(` with f-string |
| **.format() SQL**                | `critical` | Regex: `SELECT/INSERT/UPDATE/DELETE` with `.format(`         |
| **% formatting SQL**             | `critical` | Regex: SQL with `%` string formatting                        |
| **String concatenation SQL**     | `critical` | Regex: SQL with `+` concatenation                            |
| **Template literal SQL (JS/TS)** | `critical` | Regex: backtick SQL with `${` interpolation                  |


#### NoSQL Injection


| Risk                                | Severity   | How VibeLint Catches It                                                              |
| ----------------------------------- | ---------- | ------------------------------------------------------------------------------------ |
| **req.body/query/params → MongoDB** | `critical` | Regex: `find`, `findOne`, etc. with `req.body`, `req.query`, `req.params`            |
| **request.json/args → PyMongo**     | `critical` | Regex: `find_one`, `update_one`, etc. with `request.json`, `request.args`            |
| **$where with variable**            | `critical` | Regex: `$where` with variable input                                                  |
| **$ operators with user input**     | `critical` | Regex: `$ne`, `$gt`, `$in`, etc. populated from `req`, `request`, `user_input`, etc. |
| **JSON.parse → MongoDB**            | `high`     | Regex: MongoDB methods with `JSON.parse(`                                            |
| **json.loads → PyMongo**            | `high`     | Regex: PyMongo methods with `json.loads(`                                            |


#### XSS / DOM Injection


| Risk                                          | Severity   | How VibeLint Catches It                              |
| --------------------------------------------- | ---------- | ---------------------------------------------------- |
| **innerHTML/outerHTML with dynamic data**     | `high`     | Regex: `innerHTML`/`outerHTML` with `+`              |
| **eval() with variable**                      | `critical` | Regex: `eval(` with variable (not literal)           |
| **document.write with dynamic data**          | `high`     | Regex: `document.write(` with `+` or `$`             |
| **dangerouslySetInnerHTML without DOMPurify** | `high`     | Regex: `dangerouslySetInnerHTML` without `DOMPurify` |
| **Prototype pollution**                       | `high`     | Regex: `obj[req                                      |


#### Command Injection


| Risk                           | Severity   | How VibeLint Catches It                       |
| ------------------------------ | ---------- | --------------------------------------------- |
| **os.system() with variable**  | `critical` | Regex: `os.system(` with f-string or variable |
| **subprocess with shell=True** | `critical` | Regex: `subprocess.*shell = True`             |


#### Path Traversal


| Risk                                 | Severity | How VibeLint Catches It                                                                            |
| ------------------------------------ | -------- | -------------------------------------------------------------------------------------------------- |
| **open() with user-controlled path** | `high`   | Regex: `open(` with f-string or `req`, `user`, `input`, `param`, `query`, `body`, `filename`, etc. |


**Detection:** Regex-based. Comment lines skipped.

---

### 4. Missing Authentication (MissingAuthDetector)


| Risk                                      | Severity | How VibeLint Catches It                                                                                                                                       |
| ----------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Route without auth**                    | `high`   | Finds route definitions (Flask, FastAPI, Django, Express, Next.js, Spring, Go, etc.), scans ~30 lines after each route for auth evidence; flags if none found |
| **Sensitive route without authorization** | `high`   | Route has auth but no role/permission check for sensitive paths (admin, role, permission, billing, payment, etc.)                                             |


**Detection:** Regex for route patterns + auth evidence scan. Safe paths (health, static, docs, webhook) are skipped.

---

### 5. Missing Rate Limiting (RateLimitingDetector)


| Risk                                   | Severity | How VibeLint Catches It                                              |
| -------------------------------------- | -------- | -------------------------------------------------------------------- |
| **Sensitive route without rate limit** | `high`   | Login/signin/auth/token/reset/OTP routes without rate limit evidence |
| **API/write route without rate limit** | `medium` | POST/PUT/PATCH/DELETE or `/api/` routes without rate limit           |
| **Weak rate limit config**             | `low`    | `max: 0`, `windowMs: 0`, `0/minute`, `rate.Inf`, etc.                |


**Detection:** Regex for route patterns + rate limit evidence. Frameworks: Express, Flask, FastAPI, Django, Spring, Go.

---

### 6. CORS Misconfiguration (CorsDetector)


| Risk                                      | Severity | How VibeLint Catches It                             |
| ----------------------------------------- | -------- | --------------------------------------------------- |
| **Express wildcard CORS**                 | `high`   | Regex: `cors({ origin: '*' })` or `app.use(cors())` |
| **FastAPI wildcard**                      | `high`   | Regex: `allow_origins = ['*']`                      |
| **Django CORS_ORIGIN_ALLOW_ALL**          | `high`   | Regex: `CORS_ORIGIN_ALLOW_ALL = True`               |
| **Spring @CrossOrigin(origins="*")**      | `high`   | Regex: `@CrossOrigin(origins = "*")`                |
| **Go AllowedOrigins ["*"]**               | `high`   | Regex: `AllowedOrigins: []string{"*"}`              |
| **ASP.NET AllowAnyOrigin()**              | `high`   | Regex: `.AllowAnyOrigin()`                          |
| **Manual Access-Control-Allow-Origin: *** | `high`   | Regex: header set to `*`                            |


**Detection:** Regex-based. Comment lines skipped.

---

### 7. Framework Misconfiguration (FrameworkMisconfigDetector)


| Risk                                   | Severity             | How VibeLint Catches It                |
| -------------------------------------- | -------------------- | -------------------------------------- |
| **Django DEBUG=True**                  | `high` / `critical`* | Regex: `DEBUG = True`                  |
| **Django ALLOWED_HOSTS wildcard**      | `high`               | Regex: `ALLOWED_HOSTS = ['*']`         |
| **Django CSRF_COOKIE_SECURE=False**    | `medium`             | Regex: `CSRF_COOKIE_SECURE = False`    |
| **Django SESSION_COOKIE_SECURE=False** | `medium`             | Regex: `SESSION_COOKIE_SECURE = False` |
| **Flask app.run(debug=True)**          | `high` / `critical`* | Regex: `app.run(..., debug=True)`      |
| **Flask app.debug=True**               | `high` / `critical`* | Regex: `app.debug = True`              |


`*critical` when filename is `settings.py`, `production.py`, `prod.py`, `config.py`, or `wsgi.py`.

**Detection:** Regex + filename context. Python/generic only.

---

### 8. Semgrep Findings (SemgrepDetector)


| Risk                             | Severity | How VibeLint Catches It                                                                |
| -------------------------------- | -------- | -------------------------------------------------------------------------------------- |
| **Semgrep security-audit rules** | varies   | Runs Semgrep `p/security-audit` ruleset on temp file; maps findings to VibeLint format |


**Detection:** Optional. If Semgrep is not installed or times out, returns no findings. Expands coverage beyond built-in regex.

---

### 9. Prompt Injection (PromptInjectionDetector)


| Risk                                             | Severity   | How VibeLint Catches It                                                                                                                                                                                                                                                                |
| ------------------------------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Prompt injection keywords in string**          | `high`     | Regex: "ignore previous instructions", "ignore all previous", "disregard your instructions", "forget everything above", "developer mode", "dan mode", "jailbreak", "no restrictions", "system:", "new persona", "reset your context", "assistant:", "user:", "your true purpose", etc. |
| **Tainted input → AI API (direct)**              | `critical` | Regex: taint source (request.args, req.body, input(), etc.) + AI sink (openai.*.create, anthropic.*.create, etc.) without sanitizer                                                                                                                                                    |
| **Tainted input → AI API (indirect)**            | `critical` | Same as above but for indirect sources (fetch, db, file read)                                                                                                                                                                                                                          |
| **Function param → AI API without sanitization** | `high`     | AST: function parameter flows to AI call without sanitize/validate/escape                                                                                                                                                                                                              |
| **MCP escalation**                               | `critical` | Regex/AST: `arguments.get` or `args[` passed to dangerous sink (eval, exec, subprocess, os.system) without validation                                                                                                                                                                  |
| **Encoding/obfuscation near AI call**            | `high`     | Regex: `base64.b64decode`, `atob`, `rot13`, etc. near AI call                                                                                                                                                                                                                          |


**Detection:** Two-phase: (1) Regex for keywords and taint flow. (2) Python AST for multi-line taint propagation from external/user input into LLM calls without sanitization.

---

### 10. LLM Output Execution (LLMOutputExecutionDetector)


| Risk                                  | Severity   | How VibeLint Catches It                                                                                                                                                                                                          |
| ------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **LLM output → eval/exec/subprocess** | `critical` | Regex: LLM source patterns (`.choices[0].message.content`, `.message.content`, etc.) + dangerous sink (eval, exec, subprocess, os.system, child_process.exec, new Function) without allowlist/schema/validate/json.loads/sandbox |


**Detection:** Regex-based. Python and JS/TS sinks differ.

---

### 11. Vulnerable Dependencies (DependencyDetector)


| Risk                                 | Severity | How VibeLint Catches It                                                                                                    |
| ------------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Known vulnerable package version** | varies   | Parses manifest files (requirements.txt, package.json, go.mod, etc.), queries OSV API, falls back to static known-vulns DB |


**Supported manifests:** `requirements*.txt`, `Pipfile`, `pyproject.toml`, `package.json`, `package-lock.json`, `go.mod`, `Gemfile`, `Cargo.toml`, `composer.json`, `pom.xml`, `build.gradle`, `*.csproj`.

**Detection:** Filename-based manifest detection. OSV API for version lookup. Caching for performance.

---

## Setup Guide

### Option A: AI-Prompted Setup (Easiest)

Copy the content of `vibelint/MCP_SETUP.md` and give it to your AI agent (Cursor, Claude Code, Windsurf, Antigravity, etc.) with the message: **"Install this MCP for me."** The AI will handle the steps below.

---

### Option B: Manual Setup (2–3 minutes)

#### Prerequisites

- **Python 3.10 or newer** — run `python --version` or `python3 --version` to verify
- Install from [python.org/downloads](https://www.python.org/downloads/) if needed

#### Step 1: Clone and go to the vibelint folder

```bash
git clone https://github.com/elharrakrachid217-cloud/vibelint.git
cd vibelint
```

#### Step 2: Run the unified installer

```bash
python install_mcp.py
```

Use `python3` instead of `python` if that's what works on your system.

This single command:

1. Installs Python dependencies (`requirements.txt`)
2. Registers VibeLint in your IDE's MCP config (auto-detects Cursor / Windsurf / Claude Desktop)
3. Applies fail-closed enforcement rules to the current project
4. Installs a git pre-commit hook (blocks commits with security violations)
5. Registers VibeLint as a background service (auto-starts at login)

**Target a specific IDE:**

```bash
python install_mcp.py --ide cursor
python install_mcp.py --ide windsurf
python install_mcp.py --ide claude
```

**Optional flags:**


| Flag              | Effect                                |
| ----------------- | ------------------------------------- |
| `--no-enforce`    | Skip fail-closed enforcement rules    |
| `--no-pre-commit` | Skip git pre-commit hook installation |
| `--no-service`    | Skip background service registration  |


#### Step 3: Restart your IDE

- **Cursor:** Restart Cursor, or go to **Settings → MCP** and click restart next to **vibelint**
- **Windsurf / Claude Desktop:** Fully quit and reopen the app

---

### Option C: Manual MCP Configuration

If you prefer to configure MCP manually, add this to your IDE's MCP config (replace paths with your real absolute paths):

```json
{
  "mcpServers": {
    "vibelint": {
      "command": "/absolute/path/to/python",
      "args": ["/absolute/path/to/vibelint/server.py"]
    }
  }
}
```

**Important:** Use full absolute paths. Do not rely on `cwd`.


| OS      | Example                                                                                |
| ------- | -------------------------------------------------------------------------------------- |
| Windows | `"command": "C:\\Users\\you\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"` |
| macOS   | `"command": "/usr/local/bin/python3"`                                                  |
| Linux   | `"command": "/usr/bin/python3"`                                                        |


---

### Verify Installation

```bash
cd vibelint
python server.py
```

You should see: **VibeLint — AI Code Security Scanner**. Press `Ctrl+C` to stop. Your IDE will start the server automatically when needed.

---

### Updating VibeLint

The MCP does not auto-update. To get the latest fixes and features:

1. Go to your vibelint folder
2. Run `git pull` (if you installed via git clone)
3. Restart the MCP (restart the IDE, or in Cursor: **Settings → MCP** → restart **vibelint**)

---

### Fail-Closed Enforcement

When the installer runs without `--no-enforce`, it adds managed rule blocks in your project:

- `.cursorrules`
- `.windsurfrules`
- `CLAUDE.md`

These rules enforce:

1. Call `security_check` before every write
2. Use remediated output if violations are returned
3. If VibeLint MCP is unavailable, block writes and ask the user to re-enable it

---

## Troubleshooting


| Problem                             | Solution                                                                                                             |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **"Python not found"**              | Install Python from [python.org/downloads](https://www.python.org/downloads/). On Windows, tick "Add Python to PATH" |
| **"pip not found"**                 | Run `python -m pip install -r requirements.txt` manually first                                                       |
| **"No supported IDE config found"** | Use `--ide cursor`, `--ide windsurf`, or `--ide claude`                                                              |
| **"mcp package not installed"**     | Run `cd vibelint` and `python install_mcp.py` again                                                                  |
| **VibeLint doesn't appear in IDE**  | Restart the IDE. In Cursor, check **Settings → MCP** and restart **vibelint**                                        |
| **Windows "Access is denied"**      | Right-click terminal → "Run as administrator", then re-run `python install_service.py`                               |


---

## Project Structure

```
vibelint/
├── server.py                  # MCP server — entry point
├── requirements.txt
├── install_mcp.py             # Unified installer
├── install_service.py         # Background service installer
├── uninstall_service.py       # Service uninstaller
├── core/
│   ├── scanner.py             # Orchestrates all detectors
│   ├── remediator.py          # Auto-fixes violations
│   ├── logger.py              # SQLite audit log
│   └── detectors/
│       ├── base.py            # Abstract base class
│       ├── secrets.py         # Hard-coded secrets
│       ├── auth.py            # Insecure auth patterns
│       ├── injection.py       # SQL, NoSQL, XSS, command, path
│       ├── missing_auth.py    # Routes without auth
│       ├── rate_limiting.py   # Missing rate limits
│       ├── cors.py            # CORS misconfiguration
│       ├── framework_misconfig.py  # Django/Flask debug, etc.
│       ├── semgrep.py         # Semgrep integration
│       ├── prompt_injection.py    # Prompt injection
│       ├── llm_output_execution.py  # LLM output → dangerous sinks
│       └── dependencies.py    # Vulnerable dependencies
└── tests/
    ├── test_scanner.py
    ├── test_scanner_js.py
    └── test_logger.py
```

---

## Supported Languages

Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++, C#, Rust, Kotlin, Swift, Scala, Bash, Shell, HTML, JSON, YAML, Lua, R, Elixir, Terraform, Dockerfile, Generic.

---

*For the latest information, visit [www.vibelint.com](https://www.vibelint.com) or the [GitHub repository](https://github.com/elharrakrachid217-cloud/vibelint).*