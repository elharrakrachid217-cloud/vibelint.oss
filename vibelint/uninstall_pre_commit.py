#!/usr/bin/env python3
"""
Remove VibeLint pre-commit hook from .git/hooks/pre-commit.

Usage (from vibelint dir or repo root):
  python uninstall_pre_commit.py
"""

import sys
from pathlib import Path

VIBELINT_DIR = Path(__file__).resolve().parent
MARKER = "# VibeLint pre-commit hook (do not remove this marker)"


def _find_git_dir(start: Path) -> Path | None:
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


def main() -> None:
    start = Path.cwd()
    if VIBELINT_DIR != start and VIBELINT_DIR.parent != start:
        start = VIBELINT_DIR.parent
    git_dir = _find_git_dir(start)
    if not git_dir:
        print("  No .git directory found.")
        sys.exit(0)

    if git_dir.is_file():
        hooks_dir = git_dir.parent / ".git" / "hooks"
    else:
        hooks_dir = git_dir / "hooks"
    hook_file = hooks_dir / "pre-commit"

    if not hook_file.exists():
        print("  No pre-commit hook found.")
        return

    try:
        text = hook_file.read_text(encoding="utf-8")
    except OSError:
        print("  Could not read pre-commit hook.")
        sys.exit(1)

    if MARKER not in text:
        print("  pre-commit hook is not from VibeLint; leaving it unchanged.")
        return

    try:
        hook_file.unlink()
        print("  Removed VibeLint pre-commit hook.")
    except OSError as e:
        print(f"  Failed to remove hook: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
