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

### Item D — Reliability, retries, and incomplete-scan accounting
- Added `net/client.py` providing `fetch()`, `fetch_sync()`, `compute_backoff()` (3 attempts, backoff `1s`/`3s` with `0-400ms` jitter, retrying on timeout, connection reset, 0-byte body, and `502`/`503`/`504`/`408`/`429`), and `make_unreachable_finding()`.
- Updated `modules/ssl_tls.py` to retry certificate handshakes 3 times via `fetch_sync()` so transient timeouts do not emit false `"TLS handshake with certificate validation failed"` findings.
- When all 3 attempts fail on a target, emit a single `HIGH` finding `TARGET_UNREACHABLE` (`CWE-400`) and mark `result.state = "INCOMPLETE"` and `result.grade = "INCOMPLETE"` (`score = None`).
- Added per-check outcome tracking (`ran`, `skipped`, `failed`) in `core/engine.py`; when `>20%` of checks are skipped or failed, mark `result.state = "PARTIAL"` and prefix `score_display` with `~`.

### Item E — Edge / WAF challenge detection & meta-CSP separation
- Added `probe/challenge.py` detecting Cloudflare (`cf-mitigated: challenge`, `status in (403, 503)` with `"Just a moment..."` or `"challenges.cloudflare.com"`), Sucuri, Akamai, Imperva, and DataDome interstitials.
- Retried challenged responses once in `core/http_client.py` using browser `User-Agent`, `Accept`, and `Accept-Language` headers.
- When still challenged, set target banner to `EDGE-CHALLENGE (app not observed)`, tagged findings with `edge=True`, recorded `csp_source="meta"` (or `"header"`) as an `INFO` edge note (`"describes edge response"`), and suppressed application-header findings (`Missing HSTS`, `Missing CSP`, `Missing XFO`).
