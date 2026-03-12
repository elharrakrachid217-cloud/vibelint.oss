#!/usr/bin/env python3
"""
Scan a project directory with VibeLint's SecurityScanner.

Usage (from vibelint_starter root):
  python vibelint/scan_project.py
  python vibelint/scan_project.py path/to/folder

Scans code files and dependency manifest files.
Skips: tests, __pycache__, .git, node_modules, venv, .pytest_cache
"""

import os
import sys
from pathlib import Path

# Run from vibelint dir so core.scanner is importable
VIBELINT_DIR = Path(__file__).resolve().parent
if str(VIBELINT_DIR) not in sys.path:
    sys.path.insert(0, str(VIBELINT_DIR))
os.chdir(VIBELINT_DIR)

from core.scanner import SecurityScanner

EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".html": "html",
    ".sql": "generic",
    ".json": "json",
    ".toml": "generic",
    ".xml": "generic",
    ".gradle": "generic",
    ".kts": "generic",
}

MANIFEST_FILES = {
    "requirements.txt",
    "pipfile",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "go.mod",
    "gemfile",
    "cargo.toml",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}

SKIP_DIRS = {
    "__pycache__",
    ".git",
    "node_modules",
    "venv",
    ".venv",
    ".pytest_cache",
    "tests",  # optional: remove to scan test files too
}


def find_scannable_files(root: Path) -> list[tuple[Path, str]]:
    out = []
    root = root.resolve()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(s in path.parts for s in SKIP_DIRS):
            continue

        base = path.name.lower()
        ext = path.suffix.lower()

        if base in MANIFEST_FILES or base.endswith(".csproj"):
            lang = "json" if base in {"package.json", "package-lock.json", "composer.json"} else "generic"
            out.append((path, lang))
            continue

        if ext in EXT_TO_LANG:
            out.append((path, EXT_TO_LANG[ext]))
    return sorted(out, key=lambda x: str(x[0]))


def main() -> None:
    if len(sys.argv) > 1:
        project_root = Path(sys.argv[1]).resolve()
    else:
        # default: parent of vibelint (the repo root)
        project_root = VIBELINT_DIR.parent

    if not project_root.is_dir():
        print(f"Not a directory: {project_root}", file=sys.stderr)
        sys.exit(1)

    files = find_scannable_files(project_root)
    if not files:
        print(f"No scannable files under {project_root}")
        return

    scanner = SecurityScanner()
    total = 0
    failed = 0
    results = []

    print(f"VibeLint project scan: {project_root}")
    print(f"Files to scan: {len(files)}\n")

    for path, language in files:
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  [skip] {path.relative_to(project_root)}: {e}")
            continue

        rel = path.relative_to(project_root)
        result = scanner.scan(code=code, filename=str(rel), language=language)
        total += 1
        if not result["approved"]:
            failed += 1
            results.append((rel, result))

    for rel, result in results:
        print(f"  {rel}")
        summary = result["summary"].encode("ascii", "replace").decode("ascii")
        print(f"    {summary}")
        for v in result.get("violations", [])[:5]:
            desc = (v.get("description") or "")[:80].encode("ascii", "replace").decode("ascii")
            print(f"    - [{v.get('severity', '?')}] {desc}")
        if len(result.get("violations", [])) > 5:
            print(f"    ... and {len(result['violations']) - 5} more")
        print()

    print("---")
    if failed == 0:
        print(f"  All {total} file(s) passed. No security violations found.")
    else:
        print(f"  {failed} of {total} file(s) had violations. Review the output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
