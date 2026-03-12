#!/usr/bin/env python3
"""
Install VibeLint pre-commit hook into .git/hooks/pre-commit.

Usage (from vibelint dir or repo root):
  python install_pre_commit.py

The hook runs from repo root and scans only staged files.
Uninstall: python uninstall_pre_commit.py
"""

import platform
import stat
import sys
from pathlib import Path

VIBELINT_DIR = Path(__file__).resolve().parent
HOOK_SCRIPT = VIBELINT_DIR / "pre_commit_hook.py"
PYTHON_EXE = Path(sys.executable).resolve()

# Marker in hook file so uninstall can detect
MARKER = "# VibeLint pre-commit hook (do not remove this marker)"


def _step(msg: str) -> None:
    print(f"  {msg}")


def _find_git_dir(start: Path) -> Path | None:
    """Return .git dir (or file for worktrees). Start from start or cwd."""
    p = start.resolve()
    for _ in range(20):
        git = p / ".git"
        if git.exists():
            return git
        parent = p.parent
        if parent == p:
            break
        p = parent
    return None


def _repo_root(git_path: Path) -> Path:
    """Repo root from .git path."""
    if git_path.is_file():
        return git_path.parent
    return git_path.parent


def install() -> bool:
    """Install the pre-commit hook. Returns True on success, False on failure."""
    print("VibeLint pre-commit installer")
    print(f"  Python:  {PYTHON_EXE}")
    print(f"  Hook:    {HOOK_SCRIPT}")
    print()

    if not HOOK_SCRIPT.exists():
        _step(f"pre_commit_hook.py not found at {HOOK_SCRIPT}")
        return False

    start = Path.cwd()
    if VIBELINT_DIR != start and VIBELINT_DIR.parent != start:
        start = VIBELINT_DIR.parent
    git_dir = _find_git_dir(start)
    if not git_dir:
        _step("No .git directory found. Run from inside a git repo (or its vibelint subdir).")
        return False

    if git_dir.is_file():
        hooks_dir = git_dir.parent / ".git" / "hooks"
        if not hooks_dir.exists():
            _step("Worktree .git layout not supported for hook install.")
            return False
    else:
        hooks_dir = git_dir / "hooks"

    hook_file = hooks_dir / "pre-commit"
    # Include a shebang so Git for Windows can execute this hook.
    hook_body = (
        "#!/bin/sh\n"
        f"{MARKER}\n"
        'cd "$(git rev-parse --show-toplevel)" && exec '
        f'"{PYTHON_EXE}" "{HOOK_SCRIPT}"\n'
    )
    try:
        hook_file.write_text(hook_body, encoding="utf-8")
    except OSError as e:
        _step(f"Failed to write {hook_file}: {e}")
        return False

    if platform.system() != "Windows":
        try:
            st = hook_file.stat().st_mode
            hook_file.chmod(st | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass

    _step(f"Installed: {hook_file}")
    print()
    print("  Commit blocked if staged files have security violations.")
    print("  Uninstall: python uninstall_pre_commit.py")
    return True


def main() -> None:
    sys.exit(0 if install() else 1)


if __name__ == "__main__":
    main()
