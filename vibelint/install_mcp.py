#!/usr/bin/env python3
"""
install_mcp.py
==============
Unified one-command installer for VibeLint.

Runs all setup steps in order:
  1. pip install dependencies
  2. Register MCP config in your IDE
  3. Apply fail-closed enforcement rules
  4. Install git pre-commit hook
  5. Register background service

Usage:
    python install_mcp.py
    python install_mcp.py --ide cursor
    python install_mcp.py --ide claude
    python install_mcp.py --ide windsurf
    python install_mcp.py --enforce-project /path/to/project
    python install_mcp.py --no-enforce
    python install_mcp.py --no-pre-commit
    python install_mcp.py --no-service

Default behavior:
- Installs Python dependencies from requirements.txt.
- Applies fail-closed enforcement rules to the current project directory.
- Installs a git pre-commit hook (if inside a git repo).
- Registers VibeLint as a background service.
- Use --no-enforce to skip rule files, --no-pre-commit / --no-service to skip those steps.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

VIBELINT_DIR = Path(__file__).parent.resolve()


def _ping_install_telemetry() -> None:
    """Fire-and-forget ping to Supabase mcp_installs on install. Never blocks or raises."""
    if os.getenv("VIBELINT_TELEMETRY", "").lower() in ("off", "false", "0"):
        return
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_ANON_KEY", "")
    if not url or not key or "your-project" in url:
        return
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        return
    try:
        raw = platform.node() + str(uuid.getnode())
        machine_id = hashlib.sha256(raw.encode()).hexdigest()
        last_seen = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        from core.version import get_version
        version = get_version()
        payload = json.dumps({
            "machine_id": machine_id,
            "os": platform.system(),
            "platform": platform.platform(),
            "version": version,
            "last_seen": last_seen,
        })
        base_path = parsed.path.rstrip("/")
        endpoint = f"{base_path}/rest/v1/mcp_installs" if base_path else "/rest/v1/mcp_installs"
        headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=minimal",
        }
        conn = http.client.HTTPSConnection(parsed.netloc, timeout=3)
        conn.request("POST", endpoint, body=payload.encode(), headers=headers)
        response = conn.getresponse()
        response.read()
        conn.close()
    except Exception:
        pass
SERVER_PY = VIBELINT_DIR / "server.py"
PYTHON_EXE = Path(sys.executable).resolve()

IDE_CONFIG_LOCATIONS = {
    "cursor": {
        "Windows": Path.home() / ".cursor" / "mcp.json",
        "Darwin":  Path.home() / ".cursor" / "mcp.json",
        "Linux":   Path.home() / ".cursor" / "mcp.json",
    },
    "windsurf": {
        "Windows": Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
        "Darwin":  Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
        "Linux":   Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
    },
    "claude": {
        "Windows": Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        "Darwin":  Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        "Linux":   Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
    },
}

VIBELINT_ENTRY = {
    "command": str(PYTHON_EXE),
    "args": [str(SERVER_PY)],
}

_MANAGED_START = "# VIBELINT_ENFORCEMENT_START"
_MANAGED_END = "# VIBELINT_ENFORCEMENT_END"

_ENFORCEMENT_BLOCK = """VibeLint fail-closed enforcement rules:

1) Before any file write (create/modify/patch), call MCP tool `security_check`
   with the COMPLETE final file contents.
2) If `security_check` returns violations, write ONLY the returned remediated code.
3) If MCP server `vibelint` is unavailable or `security_check` cannot run,
   DO NOT write files. Stop and ask the user to re-enable VibeLint.
4) This rule applies to every language and every file, even small edits.
"""


def _step(msg: str) -> None:
    print(f"  {msg}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install VibeLint MCP config into your IDE.")
    parser.add_argument(
        "--ide",
        choices=("cursor", "windsurf", "claude"),
        help="Install only for one IDE. By default auto-detects installed IDEs.",
    )
    parser.add_argument(
        "--enforce-project",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Additional project path for fail-closed enforcement rules "
            "(.cursorrules, .windsurfrules, CLAUDE.md). "
            "Can be passed multiple times."
        ),
    )
    parser.add_argument(
        "--no-enforce",
        action="store_true",
        help="Skip default fail-closed rule installation in the current project.",
    )
    parser.add_argument(
        "--no-pre-commit",
        action="store_true",
        help="Skip git pre-commit hook installation.",
    )
    parser.add_argument(
        "--no-service",
        action="store_true",
        help="Skip background service registration.",
    )
    return parser.parse_args()


def _detect_ides() -> list[str]:
    os_name = platform.system()
    found = []
    for ide, paths in IDE_CONFIG_LOCATIONS.items():
        cfg = paths.get(os_name)
        if cfg and (cfg.exists() or cfg.parent.exists()):
            found.append(ide)
    return found


def _get_config_path(ide: str) -> Path:
    os_name = platform.system()
    paths = IDE_CONFIG_LOCATIONS.get(ide, {})
    cfg = paths.get(os_name)
    if not cfg:
        print(f"\n  [X] No known config path for '{ide}' on {os_name}")
        sys.exit(1)
    return cfg


def _read_config(path: Path) -> dict:
    if not path.exists():
        return {"mcpServers": {}}
    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return {"mcpServers": {}}
        return json.loads(text)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"\n  [X] Failed to read {path}: {exc}")
        sys.exit(1)


def _write_config(path: Path, config: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            json.dumps(config, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"\n  [X] Failed to write {path}: {exc}")
        sys.exit(1)


def _install_for_ide(ide: str) -> bool:
    cfg_path = _get_config_path(ide)
    _step(f"Config: {cfg_path}")

    config = _read_config(cfg_path)
    if "mcpServers" not in config:
        config["mcpServers"] = {}

    old_entry = config["mcpServers"].get("vibelint")
    if old_entry == VIBELINT_ENTRY:
        _step("Already installed with correct paths. Nothing to do.")
        return True

    if old_entry:
        _step("Existing vibelint entry found; replacing with correct paths ...")
    else:
        _step("Adding vibelint to MCP config ...")

    config["mcpServers"]["vibelint"] = VIBELINT_ENTRY
    _write_config(cfg_path, config)
    _step(f"Wrote config to {cfg_path}")
    return True


def _merge_managed_block(existing: str, block: str) -> str:
    managed = f"{_MANAGED_START}\n{block.strip()}\n{_MANAGED_END}\n"
    if _MANAGED_START in existing and _MANAGED_END in existing:
        start = existing.index(_MANAGED_START)
        end = existing.index(_MANAGED_END) + len(_MANAGED_END)
        replaced = existing[:start] + managed.rstrip("\n") + existing[end:]
        return replaced.rstrip() + "\n"

    existing = existing.rstrip()
    if existing:
        return existing + "\n\n" + managed
    return managed


def _write_enforcement_file(path: Path) -> None:
    current = ""
    if path.exists():
        current = path.read_text(encoding="utf-8")
    merged = _merge_managed_block(current, _ENFORCEMENT_BLOCK)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(merged, encoding="utf-8")


def _apply_enforcement(project_root: Path) -> bool:
    if not project_root.exists() or not project_root.is_dir():
        _step(f"x Invalid --enforce-project path: {project_root}")
        return False

    targets = [
        project_root / ".cursorrules",
        project_root / ".windsurfrules",
        project_root / "CLAUDE.md",
    ]

    try:
        for path in targets:
            _write_enforcement_file(path)
        _step(f"Applied fail-closed enforcement rules in: {project_root}")
        return True
    except OSError as exc:
        _step(f"x Failed to write enforcement rules in {project_root}: {exc}")
        return False


def _verify() -> bool:
    ok = True

    if not SERVER_PY.exists():
        _step(f"[X] server.py not found at {SERVER_PY}")
        ok = False

    if not PYTHON_EXE.exists():
        _step(f"[X] Python executable not found at {PYTHON_EXE}")
        ok = False

    try:
        import mcp  # noqa: F401
    except ImportError:
        _step("[X] 'mcp' package not installed. Run: pip install -r requirements.txt")
        ok = False

    return ok


def _install_dependencies() -> bool:
    """Run pip install -r requirements.txt. Returns True on success."""
    req_file = VIBELINT_DIR / "requirements.txt"
    if not req_file.exists():
        _step(f"[!] requirements.txt not found at {req_file}, skipping pip install.")
        return True

    print("\n  [1/5] Installing dependencies ...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
        cwd=str(VIBELINT_DIR),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        _step("[!] pip install failed (dependencies may already be present):")
        for line in (result.stderr or result.stdout).strip().splitlines()[-3:]:
            _step(f"   {line}")
        return True  # warn but continue
    _step("[OK] Dependencies installed.")
    return True


def main() -> None:
    args = _parse_args()

    # Ensure sibling installers are importable when script is run from any cwd
    if str(VIBELINT_DIR) not in sys.path:
        sys.path.insert(0, str(VIBELINT_DIR))

    # Load .env from vibelint/ and project root for Supabase telemetry
    try:
        from dotenv import load_dotenv
        load_dotenv(VIBELINT_DIR / ".env")
        load_dotenv(VIBELINT_DIR.parent / ".env")
    except ImportError:
        pass

    print("VibeLint Unified Installer")
    print(f"  Python:    {PYTHON_EXE}")
    print(f"  Server:    {SERVER_PY}")

    # ── Step 1: pip install dependencies ─────────────────────────────
    _install_dependencies()

    # ── Verify prerequisites ─────────────────────────────────────────
    print()
    if not _verify():
        print("\n  Fix the issues above and try again.")
        sys.exit(1)

    # ── Step 2: MCP config ───────────────────────────────────────────
    print("\n  [2/5] Registering MCP config ...")
    if args.ide:
        targets = [args.ide]
    else:
        targets = _detect_ides()
        if not targets:
            print("  No supported IDE config found. Use --ide to specify one:")
            print("    python install_mcp.py --ide cursor")
            print("    python install_mcp.py --ide windsurf")
            print("    python install_mcp.py --ide claude")
            sys.exit(1)

    all_ok = True
    for ide in targets:
        print(f"\n  [{ide.title()}]")
        if not _install_for_ide(ide):
            all_ok = False

    # ── Step 3: Enforcement rules ────────────────────────────────────
    print("\n  [3/5] Enforcement rules ...")
    if args.no_enforce:
        _step("Skipped (--no-enforce).")
    elif not args.enforce_project:
        default_project = Path.cwd().resolve()
        print(f"\n  [Enforcement] {default_project} (default)")
        if not _apply_enforcement(default_project):
            all_ok = False
    for raw_path in args.enforce_project:
        project_root = Path(raw_path).expanduser().resolve()
        print(f"\n  [Enforcement] {project_root}")
        if not _apply_enforcement(project_root):
            all_ok = False

    # ── Step 4: Pre-commit hook ──────────────────────────────────────
    print("\n  [4/5] Pre-commit hook ...")
    if args.no_pre_commit:
        _step("Skipped (--no-pre-commit).")
    else:
        try:
            from install_pre_commit import install as install_pre_commit_hook
            if not install_pre_commit_hook():
                _step("[!] Pre-commit hook was not installed (no .git found?). Continuing.")
        except Exception as exc:
            _step(f"[!] Pre-commit hook failed: {exc}. Continuing.")

    # ── Step 5: Background service ───────────────────────────────────
    print("\n  [5/5] Background service ...")
    if args.no_service:
        _step("Skipped (--no-service).")
    else:
        try:
            from install_service import install as install_background_service
            if not install_background_service():
                _step("[!] Background service installation failed. Continuing.")
        except Exception as exc:
            _step(f"[!] Background service failed: {exc}. Continuing.")

    # ── Summary ──────────────────────────────────────────────────────
    if all_ok:
        _ping_install_telemetry()
        print("\n  [OK] Done! Restart your IDE to activate VibeLint.")
        print("  (In Cursor: Settings > MCP > click restart next to vibelint)")
        if args.no_enforce:
            print("  Note: fail-closed project enforcement was skipped.")
        if args.no_pre_commit:
            print("  Note: pre-commit hook was skipped.")
        if args.no_service:
            print("  Note: background service was skipped.")
    else:
        print("\n  [X] Some installations failed. Review the errors above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
