# Changelog

## [Unreleased] — `fix-scan-accuracy`

### Item A — Temp-dir hardening & 0-byte body guard
- Added `paths.py` (`core/paths.py`) providing `tmpfile(prefix)`, `tmpdir(prefix)`, `startup_probe()`, and `validate_response_body()`.
- Startup writability probe writes, reads back, and unlinks a 1-byte file in `tempfile.gettempdir()` (falling back to `$PREFIX/tmp` and `CWD` on unconfigured Termux), aborting with exit code `3` and `"no writable temp directory"` on failure.
- Updated `core/http_client.py` to treat 0-byte HTTP responses (without `Content-Length: 0` or bodyless RFC status/method) as failed fetches rather than valid empty bodies.
- Replaced hardcoded `/tmp/sqlmap` in `config/tools.yaml` with `{dir}` and wired `core/tool_runner.py` to `paths.tmpdir()`.

### Item B — Per-host Soft-404 calibration, SPA fingerprinting, and content-signature gate
- Added `probe/soft404.py` performing 3 random 8-character path probes per host, normalizing HTML (`<script>`/`<style>` stripped, whitespace collapsed, lowercased), and computing MD5 + length baselines.
- Classified responses as Soft-404 when MD5 matches any baseline sample or `(status == baseline.status and abs(len - baseline.len) < max(80, 1% baseline.len))`.
- Enforced strict content-signature regex gates (`CONTENT_SIGNATURES`) for `.env`, `wp-config.php.bak`, `swagger-ui.html`, `.git/config`, `/admin`, etc., so HTTP 200 alone never raises an exposure finding.
- Added SPA shell fingerprinting (`data-capo`, `__next_f`, `__NUXT__`, `id="app"`, `id="root"`), unstable baseline detection (`>25%` length spread downgrades path findings one level), and `--no-soft404` CLI flag.

### Item C — Context-aware XSS classifier & two-payload agreement
- Added `probe/context.py` implementing `classify(body, offset)` returning `MARKUP | ATTR_SINGLE | ATTR_DOUBLE | ATTR_UNQUOTED | JS_STRING | JSON | COMMENT | TEXT`.
- Prevented URL-decoding of HTTP response bodies prior to tag survival checks so URL-encoded (`%3C`) or unicode-escaped (`\u003c`) reflections inside Next.js RSC flight data (`self.__next_f.push`) are classified as `JS_STRING` (`INFO` / `NEEDS MANUAL VERIFICATION`) instead of `MARKUP`.
- Enforced two-payload agreement in `modules/vulnerability_indicators.py`: `MARKUP` reflections are only promoted to `HIGH` / `CONFIRMED` when a second harmless tag probe with an independent random 10-character token also survives unescaped in `MARKUP` context; otherwise capped at `MEDIUM` / `NEEDS MANUAL VERIFICATION`.
- Recorded `context: <CLASS>` in the finding's `evidence` field.
