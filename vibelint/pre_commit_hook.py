#!/usr/bin/env python3
"""
VibeLint pre-commit hook: scan staged files for security issues.

Run from repo root (git sets cwd when the hook runs). Scans only staged
changes; blocks commit if any violations are found.

Usage (invoked by git or install script):
  python vibelint/pre_commit_hook.py   # from repo root

Optional (future):
  python vibelint/pre_commit_hook.py --fix   # auto-apply remediated code
"""

import os
import subprocess
import sys
from pathlib import Path

# Resolve vibelint dir and ensure core.scanner is importable
HOOK_DIR = Path(__file__).resolve().parent
if str(HOOK_DIR) not in sys.path:
    sys.path = [str(HOOK_DIR), *sys.path]
os.chdir(HOOK_DIR)

from core.scanner import SecurityScanner

EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".html": "html",
    ".sql": "generic",
}

SKIP_PATH_PREFIXES = (
    "vibelint/core/detectors/",
    "vibelint/tests/",
    "tests/",
)


def get_repo_root() -> Path:
    """Repo root: GIT_WORK_TREE if set, else cwd (git runs hook from work tree)."""
    root = os.environ.get("GIT_WORK_TREE")
    if root:
        return Path(root).resolve()
    return Path.cwd().resolve()


def get_staged_paths(repo_root: Path) -> list[str]:
    """Return list of staged file paths (ACMR = added, copied, modified, renamed)."""
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [p.strip() for p in out.stdout.splitlines() if p.strip()]


def get_staged_content(repo_root: Path, path: str) -> str | None:
    """Read staged (index) version of path. Returns None if unreadable."""
    try:
        out = subprocess.run(
            ["git", "show", f":{path}"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if out.returncode != 0:
            return None
        return out.stdout
    except Exception:
        return None


def main() -> int:
    repo_root = get_repo_root()
    staged = get_staged_paths(repo_root)
    if not staged:
        return 0

    # Filter to scannable extensions
    to_scan = []
    for path in staged:
        normalized = path.replace("\\", "/")
        if normalized.startswith(SKIP_PATH_PREFIXES):
            continue
        ext = Path(path).suffix.lower()
        if ext in EXT_TO_LANG:
            to_scan.append((path, EXT_TO_LANG[ext]))

    if not to_scan:
        return 0

    scanner = SecurityScanner()
    failed = []
    for path, language in to_scan:
        code = get_staged_content(repo_root, path)
        if code is None:
            continue
        result = scanner.scan(code=code, filename=path, language=language)
        if not result["approved"]:
            failed.append((path, result))

    if not failed:
        return 0

    print("VibeLint pre-commit: security violations in staged files\n")
    for path, result in failed:
        summary = (result.get("summary") or "").encode("ascii", "replace").decode("ascii")
        print(f"  {path}")
        print(f"    {summary}")
        for v in result.get("violations", [])[:5]:
            desc = (v.get("description") or "")[:80].encode("ascii", "replace").decode("ascii")
            print(f"    - [{v.get('severity', '?')}] {desc}")
        if len(result.get("violations", [])) > 5:
            print(f"    ... and {len(result['violations']) - 5} more")
        print()
    print("Fix the issues above or run: python vibelint/scan_project.py")
    return 1


if __name__ == "__main__":
    sys.exit(main())
