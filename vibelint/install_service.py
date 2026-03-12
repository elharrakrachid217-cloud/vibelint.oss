#!/usr/bin/env python3
"""
install_service.py
==================
Register VibeLint as a background service on Windows, macOS, or Linux.

Usage:
    python install_service.py

What it does:
  - Auto-detects the OS and the correct service mechanism
  - Registers VibeLint's server.py to start automatically at login
  - Redirects output to vibelint/logs/vibelint.log
  - Starts the service immediately (no reboot needed)
"""

import os
import platform
import stat
import subprocess
import sys
from pathlib import Path

# ── Auto-detected paths (never hard-coded) ──────────────────────────
VIBELINT_DIR = Path(__file__).parent.resolve()
SERVER_PY = VIBELINT_DIR / "server.py"
PYTHON_EXE = Path(sys.executable).resolve()
LOG_DIR = VIBELINT_DIR / "logs"
LOG_FILE = LOG_DIR / "vibelint.log"

# ── Service identifiers ─────────────────────────────────────────────
TASK_NAME = "VibeLint"
RUNNER_BAT = VIBELINT_DIR / "_service_runner.bat"

PLIST_LABEL = "com.vibelint.server"
PLIST_PATH = (
    Path.home() / "Library" / "LaunchAgents" / f"{PLIST_LABEL}.plist"
)

SYSTEMD_UNIT = "vibelint.service"
SYSTEMD_DIR = Path.home() / ".config" / "systemd" / "user"
SYSTEMD_PATH = SYSTEMD_DIR / SYSTEMD_UNIT


def _step(msg: str) -> None:
    print(f"  {msg}")


def _ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _step(f"✓ Log directory: {LOG_DIR}")


def _make_executable(path: Path) -> None:
    try:
        current = path.stat().st_mode
        path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        _step(f"✓ Made executable: {path.name}")
    except OSError:
        pass


# ═════════════════════════════════════════════════════════════════════
# Windows — Task Scheduler
# ═════════════════════════════════════════════════════════════════════

def _is_registered_windows() -> bool:
    try:
        r = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK_NAME],
            capture_output=True, text=True,
        )
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _install_windows() -> bool:
    print("\n🪟  Detected: Windows")
    print("  Installing via Task Scheduler …\n")

    if _is_registered_windows():
        _step(f"⚠  Task '{TASK_NAME}' is already registered.")
        _step("Run uninstall_service.py first if you want to re-register.")
        return True

    _ensure_log_dir()

    bat_lines = [
        "@echo off",
        f'"{PYTHON_EXE}" "{SERVER_PY}" >> "{LOG_FILE}" 2>&1',
    ]
    try:
        RUNNER_BAT.write_text("\r\n".join(bat_lines) + "\r\n", encoding="utf-8")
        _step(f"✓ Runner script: {RUNNER_BAT}")
    except PermissionError:
        _step(f"✗ Permission denied writing {RUNNER_BAT}")
        return False

    try:
        result = subprocess.run(
            [
                "schtasks", "/Create",
                "/TN", TASK_NAME,
                "/TR", str(RUNNER_BAT),
                "/SC", "ONLOGON",
                "/F",
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if "access" in stderr.lower():
                _step("✗ Permission denied. Run this script as Administrator:")
                _step('  Right-click Terminal → "Run as administrator"')
            else:
                _step(f"✗ schtasks failed: {stderr}")
            return False
        _step(f"✓ Task '{TASK_NAME}' registered (runs at logon)")
    except FileNotFoundError:
        _step("✗ 'schtasks' command not found.")
        _step("  Detected Windows but Task Scheduler CLI is missing.")
        return False

    try:
        r = subprocess.run(
            ["schtasks", "/Run", "/TN", TASK_NAME],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            _step("✓ Task started — VibeLint is running")
        else:
            _step(f"⚠  Registered but could not start now: {r.stderr.strip()}")
    except (subprocess.CalledProcessError, OSError) as exc:
        _step(f"⚠  Registered but could not start now: {exc}")

    _step(f"\n  Logs → {LOG_FILE}")
    return True


# ═════════════════════════════════════════════════════════════════════
# macOS — launchd
# ═════════════════════════════════════════════════════════════════════

def _is_registered_mac() -> bool:
    return PLIST_PATH.exists()


def _install_mac() -> bool:
    print("\n🍎  Detected: macOS")
    print("  Installing via launchd …\n")

    if _is_registered_mac():
        _step(f"⚠  Plist already exists: {PLIST_PATH}")
        _step("Run uninstall_service.py first if you want to re-register.")
        return True

    _ensure_log_dir()
    _make_executable(SERVER_PY)

    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"\n'
        '  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        f'    <key>Label</key>\n    <string>{PLIST_LABEL}</string>\n'
        '    <key>ProgramArguments</key>\n    <array>\n'
        f'        <string>{PYTHON_EXE}</string>\n'
        f'        <string>{SERVER_PY}</string>\n'
        '    </array>\n'
        f'    <key>WorkingDirectory</key>\n    <string>{VIBELINT_DIR}</string>\n'
        f'    <key>StandardOutPath</key>\n    <string>{LOG_FILE}</string>\n'
        f'    <key>StandardErrorPath</key>\n    <string>{LOG_FILE}</string>\n'
        '    <key>RunAtLoad</key>\n    <true/>\n'
        '    <key>KeepAlive</key>\n    <true/>\n'
        '</dict>\n'
        '</plist>\n'
    )

    try:
        PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        PLIST_PATH.write_text(plist, encoding="utf-8")
        _step(f"✓ Plist written: {PLIST_PATH}")
    except PermissionError:
        _step(f"✗ Permission denied writing {PLIST_PATH}")
        _step("  Check that ~/Library/LaunchAgents/ is writable.")
        return False

    try:
        r = subprocess.run(
            ["launchctl", "load", str(PLIST_PATH)],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            _step("✓ Service loaded — VibeLint is running")
        else:
            _step(f"⚠  launchctl load returned: {r.stderr.strip()}")
    except FileNotFoundError:
        _step("✗ 'launchctl' command not found.")
        _step("  Detected macOS but launchctl is missing.")
        return False

    _step(f"\n  Logs → {LOG_FILE}")
    return True


# ═════════════════════════════════════════════════════════════════════
# Linux — systemd (user service)
# ═════════════════════════════════════════════════════════════════════

def _is_registered_linux() -> bool:
    return SYSTEMD_PATH.exists()


def _install_linux() -> bool:
    print("\n🐧  Detected: Linux")
    print("  Installing via systemd (user service) …\n")

    if _is_registered_linux():
        _step(f"⚠  Unit file already exists: {SYSTEMD_PATH}")
        _step("Run uninstall_service.py first if you want to re-register.")
        return True

    _ensure_log_dir()
    _make_executable(SERVER_PY)

    unit = (
        "[Unit]\n"
        "Description=VibeLint MCP Security Server\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={PYTHON_EXE} {SERVER_PY}\n"
        f"WorkingDirectory={VIBELINT_DIR}\n"
        f"StandardOutput=append:{LOG_FILE}\n"
        f"StandardError=append:{LOG_FILE}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )

    try:
        SYSTEMD_DIR.mkdir(parents=True, exist_ok=True)
        SYSTEMD_PATH.write_text(unit, encoding="utf-8")
        _step(f"✓ Unit file written: {SYSTEMD_PATH}")
    except PermissionError:
        _step(f"✗ Permission denied writing {SYSTEMD_PATH}")
        _step(f"  Check that {SYSTEMD_DIR} is writable.")
        return False

    try:
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            capture_output=True, text=True, check=True,
        )
        subprocess.run(
            ["systemctl", "--user", "enable", SYSTEMD_UNIT],
            capture_output=True, text=True, check=True,
        )
        _step("✓ Service enabled (auto-starts at login)")
        subprocess.run(
            ["systemctl", "--user", "start", SYSTEMD_UNIT],
            capture_output=True, text=True, check=True,
        )
        _step("✓ Service started — VibeLint is running")
    except FileNotFoundError:
        _step("✗ 'systemctl' command not found.")
        _step("  Detected Linux but systemd is missing.")
        _step("  If using a different init system, register the service manually.")
        return False
    except subprocess.CalledProcessError as exc:
        _step(f"✗ systemctl error: {exc.stderr.strip() if exc.stderr else exc}")
        return False

    _step(f"\n  Logs → {LOG_FILE}")
    return True


# ═════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════

def install() -> bool:
    """Install VibeLint as a background service. Returns True on success, False on failure."""
    print("🔍 VibeLint Service Installer")
    print(f"  Python:  {PYTHON_EXE}")
    print(f"  Server:  {SERVER_PY}")

    os_name = platform.system()

    if os_name == "Windows":
        success = _install_windows()
    elif os_name == "Darwin":
        success = _install_mac()
    elif os_name == "Linux":
        success = _install_linux()
    else:
        print(f"\n  ✗ Unsupported OS: {os_name}")
        print("    Supported: Windows, macOS, Linux")
        return False

    if success:
        print("\n  Done! VibeLint will auto-start on next login.")
    else:
        print("\n  ✗ Installation failed. Review the errors above and try again.")

    return success


def main() -> None:
    sys.exit(0 if install() else 1)


if __name__ == "__main__":
    main()
