# Changelog

All notable changes to this project are documented in this file.

## [1.0.1] - 2026-03-09

### Added

- GitHub Actions CI workflow with Python test matrix and quality checks.
- `LICENSE` (MIT) and `SECURITY.md` policy document.
- Shared version helper at `vibelint/core/version.py`.
- `pytest.ini` to scope test discovery to `vibelint/tests`.

### Changed

- Unified runtime, telemetry, and migration version references to `1.0.1`.
- Hardened telemetry transport to require HTTPS endpoints.
- Improved detector stability for FastAPI route classification in rate limiting checks.
- Improved dependency OSV lookup transport and cleaned detector output noise.

### Fixed

- Prompt-injection AST traversal edge case around `AsyncWith` handling.
- Failing rate-limiting test now passes consistently.
