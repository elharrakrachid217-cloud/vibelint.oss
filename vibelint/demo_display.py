#!/usr/bin/env python3
"""
VibeLint Demo — Real security risks (AI-style code) and scanner results.

Run from the vibelint directory:
    python demo_display.py

Use this to record a demo: same patterns the test suite uses, so every run
produces real violations and remediations.
"""

import os
import sys

# Run from directory containing server.py so core can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from core.scanner import SecurityScanner

scanner = SecurityScanner()

# Real vulnerable snippets that look like typical AI-generated code
DEMOS = [
    {
        "name": "1. Hard-coded OpenAI API key",
        "code": 'api_key = "sk-abc123def456ghi789jkl012mno345pqr"\nclient = OpenAI(api_key=api_key)',
        "filename": "config.py",
        "language": "python",
    },
    {
        "name": "2. SQL injection (f-string in query)",
        "code": 'def get_user(user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n    return cursor.fetchone()',
        "filename": "db.py",
        "language": "python",
    },
    {
        "name": "3. MD5 password hashing",
        "code": "import hashlib\ndef hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()",
        "filename": "auth.py",
        "language": "python",
    },
    {
        "name": "4. process.env fallback bypass (JS)",
        "code": 'const apiKey = process.env.API_KEY || "sk-default-fallback-key-12345"',
        "filename": "config.js",
        "language": "javascript",
    },
    {
        "name": "5. JWT in localStorage",
        "code": 'localStorage.setItem("token", response.data.jwt)',
        "filename": "auth.js",
        "language": "javascript",
    },
    {
        "name": "6. eval(userInput)",
        "code": "const result = eval(userInput)",
        "filename": "app.js",
        "language": "javascript",
    },
]


def main():
    # Windows console may not support emoji in scanner summary; use UTF-8
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    print("=" * 60)
    print("  VibeLint Demo — AI-style code vs security scan")
    print("=" * 60)

    for demo in DEMOS:
        print("\n")
        print("-" * 60)
        print(demo["name"])
        print("-" * 60)
        print("Code (as if AI generated it):")
        print(demo["code"])
        print()

        result = scanner.scan(
            code=demo["code"],
            filename=demo["filename"],
            language=demo["language"],
        )

        print("VibeLint result:", result["summary"])
        if result["violations"]:
            for v in result["violations"]:
                print(f"  - [{v['severity']}] {v['description']}")
            print("\nRemediated code:")
            print(result["remediated_code"])
        print()

    print("=" * 60)
    print("  Demo complete. All patterns are real detector checks.")
    print("=" * 60)


if __name__ == "__main__":
    main()
