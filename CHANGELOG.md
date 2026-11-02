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

### Item F — Header correctness (duplicates, value validation, and malformed CSP)
- Added duplicate single-value header detection (`X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`) via `multi_headers` / `get_all` in `modules/http_security.py`, emitting `MEDIUM` `"Duplicate <Header> header, value invalid"`.
- Added strict value validation for `X-Frame-Options` (`DENY` | `SAMEORIGIN`), `Strict-Transport-Security` (`max-age=0` -> `MEDIUM`, `0 < max-age < 15552000` -> `LOW`, missing `max-age` -> `MEDIUM`), `X-Content-Type-Options` (`nosniff`), and `Referrer-Policy` (W3C token set).
- Added CSP directive syntax parser detecting comma-separated directives (`frame-ancestors 'self', upgrade-insecure-requests`) as `MEDIUM` `"Malformed Content-Security-Policy (comma-separated directives)"`.
- Enforced mutual exclusion so duplicate or invalid headers never also emit a separate `"missing header"` or clickjacking finding.

### Item G — Cookie severity calibration, CSRF HttpOnly exemption, and `__Host-` / `__Secure-` validation
- Added `HTTPONLY_EXEMPT = {"xsrf-token", "csrf_token", "x-csrf-token", "_csrf"}` in `modules/cookies.py` so intentionally JS-readable CSRF cookies do not trigger missing `HttpOnly` findings.
- Standardized session-like cookie regex `(?i)(session|sess_id|auth|token|jwt|sid|connect\.sid|phpsessid|jsessionid)`: missing `Secure` -> `MEDIUM`, missing `HttpOnly` -> `MEDIUM`, missing `SameSite` -> `LOW`.
- Enforced `__Host-` (`Secure` + `Path=/` + no `Domain`) and `__Secure-` (`Secure`) prefix requirements (`MEDIUM` on violation), and removed noisy session-expiry inventory findings so compliant cookie sets (`ffdiamondbd.com`, `codmshopbd.com`) produce `0` findings.

### Item H — Tool-output parsers (`wafw00f`, `arjun`, `ffuf`, and global ANSI stripping)
- Added `strip_ansi()` (`re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)`) applied to all external tool output before parsing in `core/tool_runner.py`.
- Added `parse_wafw00f_output()` keeping only `^\[\+\].*behind.*WAF` (1 finding) or `^\[-\].*No WAF` (1 `INFO` `"no WAF"` finding) and dropping all ASCII banner lines.
- Added `parse_arjun_output()` dropping `Progress` status lines and keeping only `^\[\+\].*[A-Za-z0-9_-]+$`.
- Added `parse_ffuf_output()` parsing the JSON `results[]` array into `<path> [<status>]` findings with `url`, `status`, `length`, and `words`, stripping `commandline`/local temp paths, and cross-deduping against `ctx.seen_paths`.

### Item I — Subdomain canonicalization and IP-set deduplication
- Added `canonicalize_subdomain()` in `modules/dns_security.py` lowercasing, stripping trailing dots, and collapsing repeated prefixes (`www.www.`, `mail.mail.`, `www.admin.` -> `admin.`).
- Added `dedupe_subdomains()` deduplicating discovered subdomains by `(canonical_name, resolved_ip_set)` before emitting findings.

### Item J — Scoring grade caps, global score aggregation, Cloudflare edge ports, and CMS `robots.txt` suppression
- Updated `score_counts()` and `compute_global_score()` in `core/finding.py`: capped grade at `B` when any `CRITICAL` finding exists and `A-` when any `HIGH` finding exists; computed global score as `min(per_target_scores)` when any `CRITICAL` exists, else `mean(per_target_scores)`.
- Added `score_breakdown()` returning the per-severity weight/deduction table.
- Updated `modules/infrastructure.py` (`classify_port_severity`) to classify ports `8080`/`8443` on Cloudflare-proxied hosts as `INFO` (`"edge port"`) and `LOW`/`MEDIUM` only when origin is exposed.
- Updated `modules/reconnaissance.py` to suppress standard WordPress `robots.txt` entries (`/wp-admin/`, `/wp-content/`, `/wp-includes/`, `/wp-json/`), emitting `INFO` when no other sensitive disallow paths remain.

### Item K — Report splitting, single response-header block per target, JSON schema fields, and per-target Verification sections
- Added `split_markdown_chunks()` in `core/report_manager.py` splitting Markdown reports at `100,000` characters on finding/section boundaries into `report_<ts>_<n>.md` plus `index.md`, never truncating mid-finding.
- Updated `modules/headers.py` and `core/report_manager.py` to emit the response header block once per target under the target heading while individual header findings reference the header name only.
- Added `schema_version`, `confidence`, `cwe`, `cvss`, `evidence_hash`, `first_seen`, `last_seen`, `edge`, and `check_outcome` to every JSON finding object.
- Added per-target `"Verification"` sections in Markdown reports splitting machine-confirmed findings from `NEEDS MANUAL VERIFICATION`.

### Item L — DNS topology & origin-exposure detector (`dns/topology.py`)
- Added `dns/topology.py` (with `dnspython` package bridge in `dns/__init__.py`) maintaining Cloudflare IPv4/IPv6 CIDR networks and classifying targets into `CF_PROXIED`, `CF_DNS_ONLY`, or `DIRECT`.
- When `CF_DNS_ONLY` (Cloudflare `NS` + non-Cloudflare `A`/`AAAA`), emit `MEDIUM` `"Origin IP exposed behind Cloudflare (proxy bypassed)"`, set `scan_target = origin_ip`, and emit `"Cloudflare DNS only - no WAF in path"` (`INFO`) while suppressing false Cloudflare WAF detections.
- When `>=2` `A` records resolve across distinct `/16` networks outside a single CDN anycast, emit `LOW` `"Multiple A records in distinct networks, possible split origin or dangling record"`.
