# Install VibeLint

VibeLint is an MCP server that scans AI-generated code for security issues before it reaches your files.

> **Easiest way to install:** Copy the content of this file and give it to your AI agent (Cursor, Claude Code, Windsurf, Antigravity, etc.) with the message: *"Install this MCP for me."* It will handle everything below.

---

## Before you start

You need **Python 3.10 or newer** installed on your machine. To check, open a terminal and run:

```
python --version
```

If you don't have Python, download it from [python.org](https://www.python.org/downloads/).

## Step 1 — Clone and go to the vibelint folder

```
git clone https://github.com/elharrakrachid217-cloud/vibelint.git
cd vibelint
```

## Step 2 — Run the unified installer

```
python install_mcp.py
```

One command does everything: installs Python dependencies, registers VibeLint in your IDE's MCP config, applies fail-closed enforcement rules, installs the git pre-commit hook (if in a git repo), and registers the background service. No separate `pip install` step.

To target a specific IDE:

```
python install_mcp.py --ide cursor
python install_mcp.py --ide windsurf
python install_mcp.py --ide claude
```

To enforce additional projects:

```
python install_mcp.py --enforce-project /absolute/path/to/project
```

Optional flags to skip steps:

| Flag              | Effect                                |
| ----------------- | ------------------------------------- |
| `--no-enforce`    | Skip fail-closed enforcement rules    |
| `--no-pre-commit` | Skip git pre-commit hook installation |
| `--no-service`    | Skip background service registration  |

## Step 3 — Restart your IDE

Reload or restart your IDE so it picks up the new MCP server. Done.

In Cursor: go to **Settings > MCP** and click the restart button next to vibelint.

---

## Fail-Closed Enforcement (Default)

When the unified installer runs without `--no-enforce`, it adds managed rule blocks in your current project:

- `.cursorrules`
- `.windsurfrules`
- `CLAUDE.md`

Those rules enforce:

1. Call `security_check` before every write.
2. Use remediated output if violations are returned.
3. If VibeLint MCP is unavailable, block writes and ask the user to re-enable it.

That gives you fail-closed behavior instead of best-effort behavior.

---

## Manual setup (if you prefer)

Open your IDE's MCP configuration file and add this, replacing both paths with the **real absolute paths** on your machine:

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

**Important:** Use full absolute paths for both `command` and `args`. Do **not** rely on `cwd` — some IDEs ignore it.

| OS | Example |
|----|---------|
| Windows | `"command": "C:\\Users\\you\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"` |
| macOS | `"command": "/usr/local/bin/python3"` |
| Linux | `"command": "/usr/bin/python3"` |

---

## Verify (optional)

Run this inside the `vibelint` folder:

```
python server.py
```

If you see `VibeLint — AI Code Security Scanner` — everything is working. You can close it; your IDE starts the server on its own.

---

## Troubleshooting (for AI agents and users)

**"The tool expects a string but gets a JSON object"**  
When auditing a JSON file (e.g. `package.json`), pass the **raw file content as a string** in the `code` parameter — i.e. the exact text of the file, as returned by `read_file`. Do not pass a parsed object. The server now also accepts a parsed JSON object and will stringify it, but the most reliable approach is to pass the raw string.

**"npx vibelint" or "npm install vibelint" fails**  
VibeLint is not an npm package. It is an MCP server (Python). Use the `security_check` MCP tool from your IDE, or run the scanner via Python: `python vibelint/scan_project.py` from the project root. There is no CLI like `vibelint security-check`.

---

## Keeping VibeLint Current

MCP entries do **not** refresh themselves. Your IDE runs the code at the path in your MCP config. To get the latest fixes and features:

1. In a terminal, go to the **vibelint folder** (where `server.py` lives).
2. If you used **git clone** to install:
   ```bash
   git pull
   ```
3. **Restart the MCP** (restart the IDE, or in Cursor: **Settings → MCP** → restart **vibelint**).

That’s it. New code is used on the next MCP start. To see which version you’re running, start the server manually (`python server.py`) and check the first line; we also show it when the server starts.
