from pathlib import Path

_VERSION_FILE = Path(__file__).resolve().parents[1] / "VERSION"
_DEFAULT_VERSION = "0.0.0"


def get_version() -> str:
    """Return project version from VERSION file with safe fallback."""
    try:
        value = _VERSION_FILE.read_text(encoding="utf-8").strip()
        return value or _DEFAULT_VERSION
    except OSError:
        return _DEFAULT_VERSION
