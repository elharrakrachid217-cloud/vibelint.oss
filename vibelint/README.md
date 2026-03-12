# 🔍 VibeLint

![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

VibeLint catches security vulnerabilities in AI-generated code before they're written to disk — automatically, locally, for free.

- 🔑 Hard-coded secrets (API keys, tokens, database credentials, `process.env` fallback bypasses, Next.js secrets)
- 🔐 Insecure authentication, missing auth checks, and missing rate limiting on sensitive endpoints
- 💉 Injection and runtime abuse risks (query tampering, unsafe rendering, prompt-injection sinks, dynamic execution patterns)
- 📦 Vulnerable dependencies and insecure platform config (OSV-backed SCA checks for manifests, risky CORS wildcard policies, Django/Flask production misconfig checks)

---

## Quick Start (about 2 minutes)

### 1. Clone and run the unified installer

```bash
git clone https://github.com/elharrakrachid217-cloud/vibelint.git
cd vibelint
python install_mcp.py
```

One command does everything: installs dependencies, registers VibeLint in your IDE (Cursor / Windsurf / Claude Desktop), applies fail-closed enforcement rules, installs the git pre-commit hook, and registers the background service. Use `--ide cursor`, `--ide windsurf`, or `--ide claude` to target a specific IDE. Use `--no-pre-commit` or `--no-service` to skip those steps.

### 2. Restart your IDE

Restart Cursor, Windsurf, or Claude Desktop (or in Cursor: **Settings → MCP** → restart **vibelint**). VibeLint is then active.

### 3. (Optional) Run the test suite

```bash
pytest tests/ -v
```

All tests should pass. If they do — your scanner is working.

### Manual MCP config (optional)

If you prefer to edit the IDE config by hand, add a `vibelint` entry. The typical config:

```json
{
  "mcpServers": {
    "vibelint": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/absolute/path/to/vibelint"
    }
  }
}
```

Replace `cwd` with the **absolute path** to this folder. Config locations: **Cursor** — `~/.cursor/mcp.json`; **Windsurf** — `~/.codeium/windsurf/mcp_config.json`; **Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).

---

## Installation as Background Service

The unified installer (`python install_mcp.py`) registers the background service by default. To install or reinstall it on its own:

### Install

```bash
python install_service.py
```

**What happens on each OS:**

| OS          | Mechanism                   | Service file location                              |
| ----------- | --------------------------- | -------------------------------------------------- |
| **Windows** | Task Scheduler (`schtasks`) | Visible in Task Scheduler as "VibeLint"            |
| **macOS**   | launchd (plist)             | `~/Library/LaunchAgents/com.vibelint.server.plist` |
| **Linux**   | systemd (user unit)         | `~/.config/systemd/user/vibelint.service`          |

You should see output like:

```
🔍 VibeLint Service Installer
  Python:  /usr/bin/python3
  Server:  /home/you/vibelint/server.py

🐧  Detected: Linux
  Installing via systemd (user service) …

  ✓ Log directory: /home/you/vibelint/logs
  ✓ Made executable: server.py
  ✓ Unit file written: /home/you/.config/systemd/user/vibelint.service
  ✓ Service enabled (auto-starts at login)
  ✓ Service started — VibeLint is running

  Done! VibeLint will auto-start on next login.
```

Logs are written to `vibelint/logs/vibelint.log`.

### Uninstall

```bash
python uninstall_service.py
```

This stops the service, removes the registration, and cleans up generated files.
Log files in `logs/` are preserved.

### Troubleshooting

- **Windows "Access is denied"** — right-click your terminal and choose "Run as administrator", then re-run `python install_service.py`.
- **macOS/Linux permission errors** — check that `~/Library/LaunchAgents/` (Mac) or `~/.config/systemd/user/` (Linux) is writable by your user.
- **Service registered but not running** — check `logs/vibelint.log` for errors. The most common cause is a missing dependency; run `python install_mcp.py` again to reinstall deps.

---

## Git Pre-Commit Hook

The unified installer (`python install_mcp.py`) installs the pre-commit hook by default when run inside a git repo. To install or reinstall it on its own:

### Install (from vibelint dir or repo root)

```bash
python install_pre_commit.py
```

The hook is installed into `.git/hooks/pre-commit`. Commits are blocked when staged `.py`, `.js`, `.ts`, `.tsx`, `.jsx`, `.html`, or `.sql` files contain violations.

### Uninstall

```bash
python uninstall_pre_commit.py
```

### Using the pre-commit framework

If you use [pre-commit](https://pre-commit.com), add the repo root `.pre-commit-config.yaml` and run:

```bash
pre-commit install
```

---

## How It Works

```
You describe a feature in your IDE
        ↓
The AI agent generates code
        ↓
Your IDE calls VibeLint's security_check tool via MCP
        ↓
VibeLint scans for secrets, insecure auth, injection risks
        ↓
Returns: approved ✅ or violations 🚨 + auto-fixed code
        ↓
You review and accept the clean version
```

---

## Project Structure

```
vibelint/
├── server.py                  # MCP server — entry point, this is what your IDE connects to
├── requirements.txt
├── .cursor/
│   └── mcp.json               # MCP configuration (Cursor example — adapt for your IDE)
│
├── core/
│   ├── scanner.py             # Orchestrates all detectors and returns final result
│   ├── remediator.py          # Auto-fixes violations in the code
│   ├── logger.py              # SQLite-backed audit log for scan results
│   └── detectors/
│       ├── base.py            # Abstract base class for all detectors
│       ├── secrets.py              # Hard-coded secrets detector (Python + JS/TS)
│       ├── auth.py                 # Insecure auth pattern detector
│       ├── injection.py            # SQL injection, XSS, and JS/TS injection detector
│       ├── missing_auth.py         # Missing authentication decorators / guards
│       ├── rate_limiting.py        # Missing/weak rate limiting detector for API endpoints
│       ├── cors.py                 # Runtime CORS misconfiguration detector
│       ├── framework_misconfig.py  # Django/Flask production misconfiguration detector
│       ├── semgrep.py              # Optional Semgrep-powered pattern checks
│       ├── prompt_injection.py     # Prompt injection sink detector
│       ├── llm_output_execution.py # Unsafe LLM output execution detector
│       └── dependencies.py         # Dependency SCA detector (OSV + fallback DB)
│
└── tests/
    ├── test_scanner.py         # Core scanner tests
    ├── test_scanner_js.py      # JS/TS-specific pattern tests
    ├── test_dependencies.py    # Dependency SCA tests
    └── test_logger.py          # Audit logger tests
```

---

## Adding a New Detection Pattern

1. Open the relevant detector in `core/detectors/`
2. Add a new tuple to the `*_PATTERNS` list:
   ```python
   (
       r'your_regex_pattern_here',
       "Human-readable description of the vulnerability",
       "critical"  # or "high", "medium", "low"
   ),
   ```
3. Add a test first — use `tests/test_scanner.py` for Python patterns or `tests/test_scanner_js.py` for JS/TS patterns
4. Run `pytest tests/ -v` to verify all tests pass

That's it. No other files need to change.

---

## Testing Your Scanner Manually

You can test the scanner directly from Python:

```python
from core.scanner import SecurityScanner

scanner = SecurityScanner()
result = scanner.scan(
    code='api_key = "sk-abc123verylongkey"',
    filename="app.py",
    language="python"
)
print(result["summary"])
print(result["remediated_code"])
```

---

## JS/TS Detection Coverage

| Category      | Pattern                                      | Severity |
| ------------- | -------------------------------------------- | -------- |
| **Secrets**   | `process.env.KEY \|\| "fallback"` bypass     | high     |
| **Secrets**   | Hardcoded `NEXTAUTH_SECRET` / `NEXTAUTH_URL` | critical |
| **Secrets**   | `NEXT_PUBLIC_*` variables hardcoded inline   | high     |
| **Auth**      | `localStorage.setItem("token", ...)`         | high     |
| **Auth**      | `fetch()` with credentials in URL params     | high     |
| **Auth**      | `NextAuth({ debug: true })` in production    | high     |
| **Injection** | `eval(variable)` with dynamic input          | critical |
| **Injection** | `document.write()` with user data            | high     |
| **Injection** | `dangerouslySetInnerHTML` without DOMPurify  | high     |
| **Injection** | `obj[userInput] = value` prototype pollution | high     |

All fix hints for JS/TS use `process.env.VARIABLE_NAME` syntax, not Python's `os.environ`.

---

## Roadmap

- [x] MCP server foundation
- [x] Secrets detection (regex-based)
- [x] Auth pattern detection
- [x] SQL injection + XSS detection
- [x] Runtime CORS misconfiguration detection
- [x] Framework-specific production misconfiguration detection (Django/Flask)
- [x] Rate limiting detection (missing limiter + weak limiter config)
- [x] Prompt injection sink detection
- [x] LLM output execution / sandboxing detector
- [x] Dependency SCA detection (OSV API + fallback vulnerability DB)
- [x] Auto-remediation engine
- [x] JavaScript/TypeScript pattern detection (10 new patterns)
- [x] SQLite audit logger
- [x] Integrate Yelp's detect-secrets for broader coverage
- [x] AST-based detection (implemented via Semgrep + detector-specific AST logic)
- [x] JavaScript/TypeScript AST parser (implemented via Semgrep JS/TS AST engine)
- [x] Git pre-commit hook (free tier)
- [x] Unified one-command installer (deps + MCP + enforcement + pre-commit + service)

