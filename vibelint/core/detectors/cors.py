"""
core/detectors/cors.py
======================
Detects wildcard CORS misconfigurations.

When AI agents encounter CORS errors during web development, their 
default "quick fix" is to apply a wildcard ('*') CORS policy. 
This completely disables the browser's Same-Origin Policy for the API.

This detector catches:
- Express: cors({ origin: '*' }) or app.use(cors())
- FastAPI: allow_origins=["*"]
- Django: CORS_ORIGIN_ALLOW_ALL = True
- Spring Boot: @CrossOrigin(origins = "*")
- Go: AllowedOrigins([]string{"*"})
- Manual headers: Access-Control-Allow-Origin: *
"""

import re
from core.detectors.base import BaseDetector


class CorsDetector(BaseDetector):

    CORS_PATTERNS = [
        # ── Express.js / Node.js ──
        (
            r"(?i)cors\s*\(\s*\{\s*origin\s*:\s*(?:['\"]\*['\"]|true)\s*\}\s*\)",
            "Express: Wildcard CORS policy enabled. This disables the Same-Origin Policy.",
            "high",
            "javascript"
        ),
        (
            r"(?i)app\.use\s*\(\s*cors\s*\(\s*\)\s*\)",
            "Express: Default cors() allows all origins ('*'). Specify allowed origins explicitly.",
            "high",
            "javascript"
        ),
        
        # ── FastAPI / Python ──
        (
            r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]",
            "FastAPI: Wildcard CORS policy ('*') allowed. Specify allowed origins explicitly.",
            "high",
            "python"
        ),
        
        # ── Django / Python ──
        (
            r"(?i)CORS_ORIGIN_ALLOW_ALL\s*=\s*(?:True|1)",
            "Django: CORS_ORIGIN_ALLOW_ALL is True. This disables the Same-Origin Policy.",
            "high",
            "python"
        ),
        (
            r"(?i)CORS_ALLOWED_ORIGINS\s*=\s*\[[^\]]*['\"]\*['\"][^\]]*\]",
            "Django: Wildcard CORS policy ('*') allowed. Specify allowed origins explicitly.",
            "high",
            "python"
        ),
        
        # ── Spring Boot / Java / Kotlin ──
        (
            r"(?i)@CrossOrigin\s*\(\s*origins\s*=\s*['\"]\*['\"]\s*\)",
            "Spring Boot: Wildcard CORS policy allowed via @CrossOrigin. Specify allowed origins.",
            "high",
            "java"
        ),
        (
            r"(?i)\.allowedOrigins\s*\(\s*['\"]\*['\"]\s*\)",
            "Spring Boot: Wildcard CORS policy allowed via CORS registry. Specify allowed origins.",
            "high",
            "java"
        ),

        # ── Go ──
        (
            r"(?i)AllowedOrigins\s*:\s*\[\]string\{\s*[\"']\*[\"']\s*\}",
            "Go: Wildcard CORS policy allowed. Specify allowed origins explicitly.",
            "high",
            "go"
        ),
        (
            r"(?i)AllowAllOrigins\s*:\s*true",
            "Go: AllowAllOrigins is true. This disables the Same-Origin Policy.",
            "high",
            "go"
        ),
        
        # ── ASP.NET / C# ──
        (
            r"(?i)\.AllowAnyOrigin\s*\(\s*\)",
            "ASP.NET: AllowAnyOrigin() used in CORS policy. This disables the Same-Origin Policy.",
            "high",
            "csharp"
        ),
        
        # ── Manual Headers (Any Framework) ──
        (
            r"(?i)(?:Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*['\"]?|\[['\"]Access-Control-Allow-Origin['\"]\]\s*=\s*['\"]?\*['\"]?)",
            "Wildcard Access-Control-Allow-Origin header detected. This disables the Same-Origin Policy.",
            "high",
            "generic"
        ),
        (
            r"(?i)setHeader\s*\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]\s*\)",
            "Wildcard Access-Control-Allow-Origin header detected. This disables the Same-Origin Policy.",
            "high",
            "javascript"
        ),
        (
            r"(?i)Headers\.Add\s*\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]\s*\)",
            "Wildcard Access-Control-Allow-Origin header detected. This disables the Same-Origin Policy.",
            "high",
            "csharp"
        ),
    ]

    def detect(self, code: str, language: str) -> list[dict]:
        violations = []

        # Remove comments to avoid false positives in commented-out code
        lines = code.split('\n')
        clean_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                clean_lines.append('')
            else:
                clean_lines.append(line)
        clean_code = '\n'.join(clean_lines)

        for pattern, description, severity, hint_lang in self.CORS_PATTERNS:
            for match in re.finditer(pattern, clean_code):
                # Calculate line number (1-indexed) based on match start index
                line_idx = clean_code.count('\n', 0, match.start())
                line_text = lines[line_idx].strip()
                
                # If the match spans multiple lines, grab the first line
                violations.append({
                    "type": "cors_misconfiguration",
                    "severity": severity,
                    "line": line_idx + 1,
                    "description": description,
                    "offending_line": line_text,
                    "fix_hint": self._get_fix_hint(language if language != "generic" else hint_lang)
                })

        return violations

    _CORS_FIX_HINTS: dict[str, str] = {
        "javascript": (
            "Load allowed origins from an environment variable. Example:\n"
            "  const allowedOrigins = process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',') : [];\n"
            "  app.use(cors({ origin: allowedOrigins }));"
        ),
        "typescript": (
            "Load allowed origins from an environment variable. Example:\n"
            "  const allowedOrigins = process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',') : [];\n"
            "  app.use(cors({ origin: allowedOrigins }));"
        ),
        "python": (
            "Load allowed origins from an environment variable. Example:\n"
            "  import os\n"
            "  origins = os.getenv('FRONTEND_URLS', '').split(',')\n"
            "  allow_origins=origins  # (FastAPI) or CORS_ALLOWED_ORIGINS=origins (Django)"
        ),
        "java": (
            "Load allowed origins from application properties. Example:\n"
            "  @CrossOrigin(origins = \"${app.cors.allowed-origins}\")"
        ),
        "kotlin": (
            "Load allowed origins from application properties. Example:\n"
            "  @CrossOrigin(origins = \"${app.cors.allowed-origins}\")"
        ),
        "go": (
            "Load allowed origins from an environment variable. Example:\n"
            "  origins := strings.Split(os.Getenv(\"FRONTEND_URLS\"), \",\")\n"
            "  AllowedOrigins: origins"
        ),
        "csharp": (
            "Load allowed origins from configuration. Example:\n"
            "  builder.WithOrigins(Configuration.GetSection(\"CorsOrigins\").Get<string[]>())"
        ),
    }

    def _get_fix_hint(self, language: str) -> str:
        hint = self._CORS_FIX_HINTS.get(language)
        if hint:
            return hint
        return "Configure CORS to only allow specific, trusted domains (e.g., your frontend URL) loaded from environment variables."
