# Changelog

## [Unreleased] — `fix-scan-accuracy`

### Item A — Temp-dir hardening & 0-byte body guard
- Added `paths.py` (`core/paths.py`) providing `tmpfile(prefix)`, `tmpdir(prefix)`, `startup_probe()`, and `validate_response_body()`.
- Startup writability probe writes, reads back, and unlinks a 1-byte file in `tempfile.gettempdir()` (falling back to `$PREFIX/tmp` and `CWD` on unconfigured Termux), aborting with exit code `3` and `"no writable temp directory"` on failure.
- Updated `core/http_client.py` to treat 0-byte HTTP responses (without `Content-Length: 0` or bodyless RFC status/method) as failed fetches rather than valid empty bodies.
- Replaced hardcoded `/tmp/sqlmap` in `config/tools.yaml` with `{dir}` and wired `core/tool_runner.py` to `paths.tmpdir()`.
