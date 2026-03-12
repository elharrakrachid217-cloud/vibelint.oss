"""
core/detectors/auth.py
======================
Detects dangerous authentication patterns in AI-generated code.

AI agents LOVE to generate roll-your-own auth. It always has subtle flaws.
This detector catches the most dangerous patterns.

Patterns we catch:
- MD5 or SHA1 used for password hashing (never acceptable)
- Plain text password storage
- JWT decoded without signature verification
- Hardcoded admin/bypass credentials

TODO for you to expand:
- AST-based detection (more accurate than regex for complex logic)
- Detect missing rate limiting on login endpoints
- Detect missing account lockout logic
"""

import re
from core.detectors.base import BaseDetector


class AuthDetector(BaseDetector):

    AUTH_PATTERNS = [
        # MD5 or SHA1 for passwords — completely broken
        (
            r'(?i)(hashlib\.md5|hashlib\.sha1|md5\(|sha1\()',
            "MD5/SHA1 must never be used for password hashing. Use bcrypt or argon2.",
            "critical"
        ),
        # Plain text password comparison
        (
            r'(?i)(password\s*==\s*|==\s*password)',
            "Possible plain-text password comparison detected. Passwords must be hashed and verified with a constant-time compare.",
            "critical"
        ),
        # JWT decode without verification (the 'algorithms=None' or 'verify=False' pattern)
        (
            r'(?i)jwt\.decode.*["\']?verify["\']?\s*[:=]\s*False',
            "JWT decoded with signature verification disabled. This allows token forgery.",
            "critical"
        ),
        (
            r'(?i)jwt\.decode.*algorithms\s*=\s*\[\s*["\']none["\']\s*\]',
            "JWT decoded with algorithm 'none'. This completely disables signature verification.",
            "critical"
        ),
        # Hard-coded admin credentials
        (
            r'(?i)(admin.*password|password.*admin)\s*=\s*["\'][^"\']+["\']',
            "Hard-coded admin credentials detected in source code.",
            "critical"
        ),
        # SQL-based auth without parameterized queries (caught here as auth-specific)
        (
            r'(?i)SELECT.*FROM.*users.*WHERE.*password.*["\'\+]',
            "Potential SQL injection in authentication query. Use parameterized queries.",
            "critical"
        ),
        # JS/TS: localStorage storing JWT tokens (XSS-accessible)
        (
            r'(?i)localStorage\.(setItem|getItem)\s*\(\s*["\'](?:token|jwt|auth[_-]?token|access[_-]?token|session[_-]?token|id[_-]?token)["\']',
            "Storing authentication tokens in localStorage is insecure. Use httpOnly cookies instead.",
            "high"
        ),
        # JS/TS: fetch() with credentials in URL parameters
        (
            r'(?i)fetch\s*\(.*[\?&](token|key|api_key|apiKey|secret|password|auth)=',
            "Credentials passed as URL parameters in fetch(). Use Authorization header instead.",
            "high"
        ),
        # JS/TS: NextAuth debug mode enabled (information leakage in production)
        (
            r'(?i)NextAuth\s*\(.*debug\s*:\s*true',
            "NextAuth debug mode enabled. Disable in production to prevent information leakage.",
            "high"
        ),
    ]

    def detect(self, code: str, language: str) -> list[dict]:
        violations = []
        lines = code.split('\n')

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, description, severity in self.AUTH_PATTERNS:
                if re.search(pattern, line):
                    violations.append({
                        "type": "insecure_auth",
                        "severity": severity,
                        "line": line_num,
                        "description": description,
                        "offending_line": line.strip(),
                        "fix_hint": self._get_fix_hint(language, description)
                    })
                    break

        return violations

    _AUTH_FIX_HINTS: dict[str, str] = {
        "python": (
            "For password hashing: use 'pip install bcrypt' and bcrypt.hashpw(). "
            "For JWT: use python-jose with a strong HS256 secret from environment variables. "
            "Never implement auth logic from scratch."
        ),
        "javascript": (
            "For password hashing: use 'npm install bcryptjs'. "
            "For JWT: use 'npm install jsonwebtoken' with a secret from process.env. "
            "Consider using NextAuth.js or Passport.js instead of custom auth."
        ),
        "typescript": (
            "For password hashing: use 'npm install bcryptjs'. "
            "For JWT: use 'npm install jsonwebtoken' with a secret from process.env. "
            "Consider using NextAuth.js or Passport.js instead of custom auth."
        ),
        "java": (
            "For password hashing: use BCrypt from Spring Security or jBCrypt. "
            "For JWT: use jjwt or nimbus-jose-jwt with secrets from environment variables. "
            "Consider Spring Security for a complete auth solution."
        ),
        "go": (
            "For password hashing: use golang.org/x/crypto/bcrypt. "
            "For JWT: use github.com/golang-jwt/jwt with secrets from os.Getenv(). "
            "Never roll your own authentication."
        ),
        "ruby": (
            "For password hashing: use bcrypt gem (has_secure_password in Rails). "
            "For JWT: use ruby-jwt gem with secrets from ENV. "
            "Consider Devise for a complete auth solution."
        ),
        "php": (
            "For password hashing: use password_hash() with PASSWORD_BCRYPT. "
            "For JWT: use firebase/php-jwt with secrets from getenv(). "
            "Consider Laravel Sanctum or Passport for complete auth."
        ),
        "rust": (
            "For password hashing: use the bcrypt or argon2 crate. "
            "For JWT: use jsonwebtoken crate with secrets from std::env::var(). "
            "Never implement auth primitives from scratch."
        ),
        "csharp": (
            "For password hashing: use BCrypt.Net-Next or ASP.NET Identity. "
            "For JWT: use Microsoft.IdentityModel.Tokens with secrets from IConfiguration. "
            "Consider ASP.NET Identity for a complete auth solution."
        ),
        "kotlin": (
            "For password hashing: use BCrypt from Spring Security or jBCrypt. "
            "For JWT: use jjwt with secrets from System.getenv(). "
            "Consider Spring Security for a complete auth solution."
        ),
        "swift": (
            "For password hashing: use a bcrypt implementation like Vapor's Bcrypt. "
            "For JWT: use vapor/jwt-kit with secrets from environment variables. "
            "Never implement auth primitives from scratch."
        ),
    }

    def _get_fix_hint(self, language: str, description: str = "") -> str:
        if language in ("javascript", "typescript"):
            if "localStorage" in description:
                return (
                    "Never store JWTs in localStorage — it is vulnerable to XSS attacks. "
                    "Use httpOnly cookies instead. With Next.js, use next-auth session handling. "
                    "Store secrets server-side and reference them via process.env."
                )
            if "URL parameters" in description:
                return (
                    "Never pass tokens as URL parameters — they appear in server logs and browser history. "
                    "Use the Authorization header: fetch(url, { headers: { Authorization: `Bearer ${token}` } }). "
                    "Keep secrets in process.env on the server side."
                )
            if "NextAuth" in description and "debug" in description:
                return (
                    "Disable debug mode in production. Set NEXTAUTH_SECRET in .env.local via process.env.NEXTAUTH_SECRET "
                    "and never hardcode auth configuration values."
                )

        hint = self._AUTH_FIX_HINTS.get(language)
        if hint:
            return hint
        return "Use a battle-tested auth library. Never implement password hashing or JWT handling from scratch."
