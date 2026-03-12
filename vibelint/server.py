"""
VibeLint MCP Server
====================
This is the main entry point. Any MCP-compatible IDE or AI agent calls this
server before writing AI-generated code to disk. We scan it, flag violations,
and return fixes.

Run with:
    python server.py
"""

import asyncio
import hashlib
import http.client
import io
import json
import os
import platform
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# Ensure imports work regardless of which directory the MCP client launches from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
if BASE_DIR not in sys.path:
    sys.path = [BASE_DIR] + sys.path

try:
    from dotenv import load_dotenv
    load_dotenv()
    load_dotenv(Path(BASE_DIR).parent / ".env")
except ImportError:
    pass

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from core.scanner import SecurityScanner
from core.version import get_version

SUPPORTED_LANGUAGES = [
    "python", "javascript", "typescript",
    "java", "go", "ruby", "php",
    "c", "cpp", "csharp",
    "rust", "kotlin", "swift", "scala",
    "bash", "shell",
    "html", "json", "yaml",
    "lua", "r", "elixir", "terraform", "dockerfile",
    "generic",
]

# instructions= is the MCP server-level system prompt; IDEs receive this and enforce pre-write security_check.
app = Server(
    "vibelint",
    instructions=(
        "VibeLint is a MANDATORY security gate for all code generation. "
        "You MUST call the security_check tool with the complete code contents "
        "BEFORE every file-write operation — this includes using Write, StrReplace, "
        "creating new files, or any shell command that writes code. "
        "If security_check returns violations, use the remediated code it provides "
        "instead of your original. NEVER write, save, or apply code to disk without "
        "scanning it through security_check first. This applies to EVERY code change, "
        "regardless of size or perceived risk."
    ),
)
scanner = SecurityScanner()
VERSION = get_version()

# Telemetry: anonymous unique-install tracking (opt-out via VIBELINT_TELEMETRY=off)
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")


def _ping_telemetry():
    """Fire-and-forget ping to Supabase for unique install count. Never blocks or raises."""
    if os.getenv("VIBELINT_TELEMETRY", "").lower() in ("off", "false", "0"):
        return
    if not SUPABASE_URL or not SUPABASE_ANON_KEY or "your-project" in SUPABASE_URL:
        return

    parsed = urlparse(SUPABASE_URL)
    if parsed.scheme != "https" or not parsed.netloc:
        return

    try:
        raw = platform.node() + str(uuid.getnode())
        machine_id = hashlib.sha256(raw.encode()).hexdigest()
        last_seen = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = json.dumps({
            "machine_id": machine_id,
            "os": platform.system(),
            "platform": platform.platform(),
            "version": VERSION,
            "last_seen": last_seen,
        })

        base_path = parsed.path.rstrip("/")
        endpoint = f"{base_path}/rest/v1/mcp_installs" if base_path else "/rest/v1/mcp_installs"
        headers = {
            "apikey": SUPABASE_ANON_KEY,
            "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=minimal",
        }

        conn = http.client.HTTPSConnection(parsed.netloc, timeout=3)
        conn.request("POST", endpoint, body=payload.encode(), headers=headers)
        response = conn.getresponse()
        response.read()  # consume body so connection can close cleanly
        conn.close()
    except Exception:
        pass  # never crash the MCP server for telemetry


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Expose the security_check tool as a mandatory pre-write gate."""
    return [
        Tool(
            name="security_check",
            description=(
                "REQUIRED pre-write security gate — you MUST call this tool on every code block "
                "BEFORE writing or saving any file to disk. Never skip it, even for small edits. "
                "Submit the full code you intend to write; use the returned remediated code in place "
                "of your original if violations are found. "
                "Detects: hard-coded secrets, weak authentication, SQL injection, and other vulnerabilities. "
                "Returns pass/fail status, violation details with severity, and auto-fixed code."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": (
                            "The complete code you are about to write to disk, as a single string. "
                            "Include ALL code exactly as you plan to save it — do not omit sections. "
                            "For JSON/YAML/config files: pass the raw file text (e.g. the result of read_file), not a parsed object. "
                            "If you pass a string, use it as-is; the server also accepts a parsed JSON object and will stringify it."
                        )
                    },
                    "filename": {
                        "type": "string",
                        "description": (
                            "Target filename including extension (e.g., 'auth.py', 'db.js', 'api.ts', 'main.go'). "
                            "Used to select language-specific security rules."
                        )
                    },
                    "language": {
                        "type": "string",
                        "description": "Programming language of the code block.",
                        "enum": SUPPORTED_LANGUAGES
                    }
                },
                "required": ["code", "filename", "language"]
            }
        )
    ]


def _normalize_code(code) -> str:
    """Ensure code is always a string. Some MCP clients send JSON files as parsed objects."""
    if isinstance(code, str):
        return code
    if isinstance(code, (dict, list)):
        return json.dumps(code, indent=2)
    return str(code) if code is not None else ""


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Route incoming tool calls to the security scanner."""
    if name != "security_check":
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    code = _normalize_code(arguments.get("code", ""))
    filename = arguments.get("filename", "unknown")
    language = arguments.get("language", "generic")

    # Run the security scan
    result = scanner.scan(code=code, filename=filename, language=language)

    # Format and return the result
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    threading.Thread(target=_ping_telemetry, daemon=True).start()
    print(f"VibeLint {VERSION} — AI Code Security Scanner")
    print("   Linting AI-generated code before it hits your files...\n")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    asyncio.run(main())
