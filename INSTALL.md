# VibeLint — 2‑minute setup

You don't need to know Python or MCP. Follow these steps in order; each one is a single copy‑paste.

---

## What you need

- **Python 3.10 or newer** (we'll check in Step 0).
- **This project** on your machine (e.g. you cloned or downloaded `vibelint_starter`).

---

## Step 0 — Check Python (30 seconds)

Open a **terminal**:

- **Windows:** Press `Win + R`, type `cmd`, press Enter. Or in File Explorer, type `cmd` in the address bar and press Enter.
- **Mac:** Press `Cmd + Space`, type `Terminal`, press Enter.
- **Linux:** `Ctrl+Alt+T` or open "Terminal" from your app menu.

In the terminal, run **one** of these (try the first; if it says "not found", try the second):

```bash
python --version
```

```bash
python3 --version
```

You should see something like `Python 3.10.0` or `Python 3.12.1`.  
If you get "not found" or "not recognized", install Python from [python.org/downloads](https://www.python.org/downloads/) and run this step again.

---

## Step 1 — Go to the VibeLint folder (10 seconds)

In the **same terminal**, go to this project folder, then into the `vibelint` folder.

**Windows (Command Prompt or PowerShell):**

```bash
cd path\to\vibelint_starter
cd vibelint
```

**Mac / Linux:**

```bash
cd /path/to/vibelint_starter
cd vibelint
```

Replace `path\to\vibelint_starter` (or `/path/to/vibelint_starter`) with the real path where the project lives.  
Example on Windows: `cd C:\Users\Ahmed\Downloads\vibelint_starter` then `cd vibelint`.  
Example on Mac: `cd ~/Projects/vibelint_starter` then `cd vibelint`.

---

## Step 2 — Run the unified installer (about 60 seconds)

Still in the `vibelint` folder, run **one** command:

```bash
python install_mcp.py
```

Use `python3` instead of `python` if that's what worked in Step 0.

This single command does everything:

1. Installs Python dependencies (`requirements.txt`)
2. Registers VibeLint in your IDE's MCP config (auto-detects Cursor / Windsurf / Claude Desktop)
3. Applies fail-closed enforcement rules to the current project
4. Installs a git pre-commit hook (blocks commits with security violations)
5. Registers VibeLint as a background service (auto-starts at login)

**To target a specific IDE:**

```bash
python install_mcp.py --ide cursor
python install_mcp.py --ide windsurf
python install_mcp.py --ide claude
```

**Optional flags to skip steps:**

| Flag              | Effect                                |
| ----------------- | ------------------------------------- |
| `--no-enforce`    | Skip fail-closed enforcement rules    |
| `--no-pre-commit` | Skip git pre-commit hook installation |
| `--no-service`    | Skip background service registration  |

You should see "[OK] Done! Restart your IDE to activate VibeLint."

---

## Step 3 — Restart your IDE (10 seconds)

- **Cursor:** Restart Cursor, or go to **Settings → MCP** and click the restart button next to **vibelint**.
- **Windsurf / Claude Desktop:** Fully quit the app and open it again.

---

## Verify it works — recommended

In the terminal, in the `vibelint` folder, run:

```bash
python server.py
```

You should see a line like: **VibeLint — AI Code Security Scanner** (it may take a second to appear).  
Press `Ctrl+C` to stop the server. Your IDE will start it automatically when needed.

---

## If something goes wrong

| Problem                                             | What to do                                                                                                                                         |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **"Python not found" / "python is not recognized"** | Install Python from [python.org/downloads](https://www.python.org/downloads/). On Windows, tick "Add Python to PATH" in the installer.             |
| **"pip not found"**                                 | The installer runs pip automatically. If it fails, try `python -m pip install -r requirements.txt` manually first.                                 |
| **"No supported IDE config found"**                 | Use Step 2 with `--ide cursor`, `--ide windsurf`, or `--ide claude`. Make sure that IDE has been opened at least once so its config folder exists. |
| **"'mcp' package not installed"**                   | You're not in the `vibelint` folder, or pip install didn't finish. Run `cd vibelint` and `python install_mcp.py` again.                            |
| **VibeLint doesn't appear in my IDE**               | Restart the IDE (Step 3). In Cursor, check **Settings → MCP** and restart the **vibelint** server.                                                 |

---

You're done. VibeLint will now scan AI‑generated code before it's written to your project.

## Updating VibeLint

The MCP does **not** update itself. Your IDE runs whatever code is in the folder you installed from. To get fixes and new features:

1. Open a terminal and go to your **vibelint folder** (the same folder where you ran `install_mcp.py`).
2. If you installed by **cloning the repo** (e.g. `git clone ...`):
   ```bash
   git pull
   ```
3. **Restart the MCP** (restart the IDE, or in Cursor: **Settings → MCP** → restart **vibelint**).

After that, the IDE will use the updated code. There is no separate "update command"—updating the files in that folder is enough.

If you did **not** use git (e.g. you downloaded a zip), download the latest release or clone again and run `install_mcp.py` so your IDE points at the new folder.
