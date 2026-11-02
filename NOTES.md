# Engineering Notes — Detection Decisions & False-Positive Tradeoffs

## Item A — Temp-Dir Hardening & 0-Byte Fetch Guard
- **Root Cause**: On unprivileged Android/Termux, `/tmp` does not exist at the root filesystem level (Termux uses `$PREFIX/tmp`). Any code path or external tool writing temporary artefacts to `/tmp` silently failed, yielding `0`-byte downloads. When two `0`-byte bodies were compared during differential checks, `"" == ""` made every probe look identical or masked failures.
- **Detection Decision**:
  1. Centralize all temporary file and directory allocation in `paths.tmpfile(prefix)` and `paths.tmpdir(prefix)` backed by `tempfile.gettempdir()` with fallback to `$PREFIX/tmp` and `Path.cwd()`.
  2. Execute a mandatory 1-byte write+read+unlink probe (`paths.startup_probe()`) at CLI/menu startup; abort immediately with exit code `3` (`"no writable temp directory"`) if no writable directory exists.
  3. Enforce `validate_response_body()` in `HttpClient.request()` so any `0`-byte body on a body-carrying status (`200`, `403`, `404`, `500`) without an explicit `Content-Length: 0` header is marked as a failed fetch (`ok=False`) and retried rather than compared as an empty string.
- **Tradeoff**: Legitimate HTTP/1.0 servers that close the connection with 0 bytes and omit `Content-Length: 0` are treated as failed fetches rather than valid empty pages, eliminating silent 0-byte differential false positives.

## Item B — Soft-404 Calibration, SPA Catch-All Detection & Content-Signature Gate
- **Root Cause**: 8 of 19 live targets were SPAs (Nuxt, Next.js, Vue/React) with catch-all routing returning HTTP `200` and the `index.html` bundle for `/wp-config.php.bak`, `/swagger-ui.html`, and `/admin`.
- **Detection Decision**:
  1. Calibrate each host with 3 random 8-char paths before running path probes (`probe/soft404.py`), storing status, raw byte length, and MD5 of the script/style-stripped normalized body.
  2. Classify any path response matching a baseline MD5 or within `max(80, 1% baseline_length)` at the same status as `soft-404`, downgrading to `INFO` with `"soft-404"` in `evidence`.
  3. Gate every sensitive file/path finding on an explicit content signature (`^[A-Z_][A-Z0-9_]*=` for `.env`, `<?php` for `wp-config.php.bak`, `swagger-ui|openapi` for `/swagger-ui.html`, `^\[core\]` for `.git/config`).
  4. Fingerprint SPA shells (`data-capo`, `__next_f`, `__NUXT__`, `id="app"`, `id="root"`) so all path probes on SPA hosts default to `INFO` unless their specific content signature matches.
  5. When the 3 calibration probes vary by `>25%` in length (`soft404_calibration=unstable`), downgrade verified path findings by one severity level.
- **Tradeoff**: Adds 3 lightweight calibration GET requests per host (disableable via `--no-soft404`) and requires real content signatures for exposure findings, eliminating SPA catch-all false positives at the cost of ignoring custom/redacted backup files that lack standard format headers.

## Item C — Context-Aware XSS & Two-Payload Agreement
- **Root Cause**: Next.js RSC flight payloads (`self.__next_f.push([1,"..."])`) serialize route query parameters inside JavaScript string literals with unicode escapes (`\u003e\u003cb\u003eZZ\u003c/b\u003e`), or URL-encoded strings that `urllib.parse.unquote()` previously decoded into raw `<b...>` tags before context inspection, causing 27 false-positive `HIGH` / `CONFIRMED` XSS findings across 6 hosts.
- **Detection Decision**:
  1. Never call `urllib.parse.unquote()` on the response body before checking tag survival (`C3`).
  2. Walk back up to 400 characters (and verify `<script>` enclosure) to classify reflections into `MARKUP | ATTR_SINGLE | ATTR_DOUBLE | ATTR_UNQUOTED | JS_STRING | JSON | COMMENT | TEXT` (`C1`, `C2`).
  3. Apply a single global severity/confidence matrix (`C4`): `JS_STRING`/`JSON` reflections with `\u003c` or `\"` are `INFO` / `NEEDS MANUAL VERIFICATION` (promoted to `MEDIUM` / `NEEDS MANUAL VERIFICATION` only if unescaped and paired with an explicit DOM sink like `dangerouslySetInnerHTML`, `innerHTML=`, `document.write(`, `v-html=`, or `{!!`).
  4. Require two-payload agreement (`C5`) with an independent 10-char random token before promoting any `MARKUP` reflection to `HIGH` / `CONFIRMED`.
- **Tradeoff**: Requires 1 extra HTTP GET request per genuine `MARKUP` reflection to confirm two-payload agreement, and demotes reflections inside `<script>` blocks without visible DOM sinks to `INFO` (`NEEDS MANUAL VERIFICATION`).

## Item D — Reliability, Retries & Incomplete-Scan Accounting
- **Root Cause**: A single transient TCP/TLS timeout on `bdtopupcenter.com` produced a false `HIGH` `"TLS handshake failed"` finding, silently skipped 13 downstream checks, and still awarded the target `94/A`.
- **Detection Decision**:
  1. Route HTTP and TLS connection probes through 3-attempt retry helpers (`net/client.py`: `fetch` and `fetch_sync`) with `1s` / `3s` backoff and `0-400ms` jitter (`D1`).
  2. When all 3 attempts fail (`D2`), suppress single-timeout TLS/HTTPS noise, emit one `HIGH` `TARGET_UNREACHABLE` finding, and set `state = "INCOMPLETE"`, `grade = "INCOMPLETE"`, and `score = None`.
  3. Track per-module/check outcomes (`ran`, `skipped`, `failed`) on `TargetScanResult.checks_account` (`D3`).
  4. When `>20%` of checks on a reachable target are `skipped` or `failed` (`D4`), set `state = "PARTIAL"`, format `score_display` as `~<score> (partial: <ran>/<total> checks ran)`, and exclude the target from the global score average.
- **Tradeoff**: Unreachable hosts wait ~4–4.8s across 3 retry attempts before being marked `INCOMPLETE`, trading slightly longer scan times on dead hosts for zero single-timeout false positives.

## Item E — Edge / WAF Challenge Interstitial Detection
- **Root Cause**: `diamondtopupbd.com` and `gamebuybd.com` returned HTTP `403` `"Just a moment..."` Cloudflare challenge pages on all attempts. The scanner previously parsed `<meta http-equiv="content-security-policy">` inside the Cloudflare interstitial HTML as the application's CSP and raised missing application header findings against the challenge page.
- **Detection Decision**:
  1. Detect Cloudflare, Sucuri, Akamai, Imperva, and DataDome interstitials (`probe/challenge.py`, `E1`).
  2. Retry once with a browser `User-Agent` + `Accept` + `Accept-Language` (`E2`).
  3. If still challenged (`E3`), set `edge_banner = "EDGE-CHALLENGE (app not observed)"`, tag findings with `edge=True`, record `csp_source="meta"` (or `"header"`) on an `INFO` edge note (`"describes edge response"`), and suppress all application-header claims (`Missing HSTS`, `Missing CSP`, `Missing XFO`) and downstream app-layer probes.
- **Tradeoff**: Challenged targets cannot have their origin application headers or paths audited without origin IP discovery or WAF allowlisting, but reports now honestly state `EDGE-CHALLENGE (app not observed)` with `0` bogus application-header findings.

## Item F — Header Correctness (Duplicate Single-Value Headers & CSP Syntax)
- **Root Cause**: `vertexbazaar.com` and `topupsbd.com` emitted `X-Frame-Options` twice (`DENY` and `SAMEORIGIN`) and `X-Content-Type-Options` twice as separate header lines, while `ffdiamondbd.com` emitted `frame-ancestors 'self', upgrade-insecure-requests` separated by a comma instead of a semicolon. Presence-only checks previously passed both.
- **Detection Decision**:
  1. Inspect `resp.multi_headers` and `resp.get_all()` for `X-Frame-Options`, `X-Content-Type-Options`, and `Strict-Transport-Security` (`F1`). Multiple occurrences emit `MEDIUM` `"Duplicate <Header> header, value invalid"`.
  2. Validate header values (`F2`): `X-Frame-Options` (`DENY` or `SAMEORIGIN`), `Strict-Transport-Security` (`max-age=0` -> `MEDIUM`, `<15552000` -> `LOW`), `X-Content-Type-Options` (`nosniff`), and `Referrer-Policy` (W3C token allowlist).
  3. Split `Content-Security-Policy` on `';'` (`F3`) and flag any directive containing `','` as `MEDIUM` `"Malformed Content-Security-Policy (comma-separated directives)"`.
  4. Never emit both `"missing header"` (or missing-XFO clickjacking) and `"duplicate invalid"` for the same header (`F4`).
- **Tradeoff**: None; RFC/W3C grammar violations and duplicate single-value headers are deterministically detected from already-fetched response headers.

## Item G — Cookie Severity Calibration & CSRF Exemption
- **Root Cause**: Laravel's `XSRF-TOKEN` cookie (intentionally readable by JavaScript so Axios/Angular can echo it in `X-XSRF-TOKEN`) was flagged `MEDIUM` for missing `HttpOnly`, and every session cookie without `Max-Age`/`Expires` emitted a noisy `INFO` finding even when all security flags (`Secure`, `HttpOnly`, `SameSite=Lax`) were properly set.
- **Detection Decision**:
  1. Exempt `HTTPONLY_EXEMPT = {"xsrf-token", "csrf_token", "x-csrf-token", "_csrf"}` from `HttpOnly` checks (`G1`).
  2. Match session-like cookies via `(?i)(session|sess_id|auth|token|jwt|sid|connect\.sid|phpsessid|jsessionid)` (`G2`): missing `Secure` -> `MEDIUM`, missing `HttpOnly` -> `MEDIUM`, missing `SameSite` -> `LOW`.
  3. Enforce `__Host-` (`Secure` + `Path=/` + no `Domain`) and `__Secure-` (`Secure`) prefixes at `MEDIUM` severity (`G3`).
  4. Suppress `0`-issue session-cookie inventory noise so properly configured cookie sets (`ffdiamondbd_cookies.txt`, `codmshopbd_cookies.txt`) emit `0` findings (`G4`).
- **Tradeoff**: Custom applications that store session JWTs inside a cookie named `XSRF-TOKEN` would not be flagged for missing `HttpOnly`, which is standard double-submit CSRF design.

## Item H — External Tool Output Parsers (`wafw00f`, `arjun`, `ffuf`) & ANSI Stripping
- **Root Cause**: Line-mode tool parsing previously emitted every `wafw00f` ASCII banner line (20 findings per target) with raw `\x1b[...` ANSI escape sequences, parsed `arjun`'s `[!] Progress: 36%` terminal updates as discovered parameters, and dumped `ffuf`'s top-level JSON wrapper (including `commandline` and local temp file paths) as a single blob.
- **Detection Decision**:
  1. Strip ANSI escape codes (`\x1b\[[0-9;]*[a-zA-Z]`) globally prior to parsing any tool output (`H1`).
  2. Parse `wafw00f` via `^\[\+\].*behind.*WAF` (1 finding) or `^\[-\].*No WAF` (1 `INFO` `"no WAF"`), discarding all ASCII art (`H2`).
  3. Filter `arjun` lines to drop any line containing `Progress` and match `^\[\+\].*[A-Za-z0-9_-]+$` (`H3`).
  4. Parse `ffuf` `results[]` JSON entries into `<path> [<status>]` findings with `{url, status, length, words}`, dropping `commandline`/temp paths and deduplicating against `ctx.seen_paths` (`H4`).
- **Tradeoff**: Non-standard custom forks of `wafw00f` or `arjun` that change their `[+]`/`[-]` output prefix will be ignored rather than emitting raw unparsed stdout lines.

## Item I — Subdomain Canonicalization & Deduplication
- **Root Cause**: Subdomain discovery previously emitted nested/redundant prefixes (`mail.mail.`, `www.admin.`, `www.www.`) and duplicate records without normalizing names or resolved IP sets.
- **Detection Decision**:
  1. Canonicalize subdomain candidates via `canonicalize_subdomain()` (`I1`): lowercase, strip trailing dot, collapse consecutive identical labels (`mail.mail.` -> `mail.`), and strip leading `www.` when followed by another subdomain label (`www.admin.` -> `admin.`).
  2. Deduplicate resolved entries by `(canonical_name, resolved_ip_set)` (`I2`) prior to emitting findings.
- **Tradeoff**: Intentional multi-level `www.<sublabel>.<apex>` hosts are collapsed to `<sublabel>.<apex>`, eliminating recursive prefix noise on wildcard/CNAME zones.

## Item J — Scoring Grade Caps, Edge Port Severity & CMS `robots.txt` Suppression
- **Root Cause**: Averaging per-target scores hid single-target `CRITICAL` findings behind an overall `90/100 (A)` grade; Cloudflare anycast ports `8080`/`8443` and standard WordPress `/wp-admin/` `robots.txt` entries inflated finding counts.
- **Detection Decision**:
  1. Cap grades at `B` whenever any `CRITICAL` is present and at `A-` whenever any `HIGH` is present (`J1`).
  2. Compute global score as `min(per_target_scores)` when any `CRITICAL` exists across valid targets, else `mean(per_target_scores)` (`J2`), and include the deduction breakdown table (`J3`).
  3. Classify ports `8080`/`8443` on `CF_PROXIED` hosts as `INFO` (`"edge port"`), raising `LOW`/`MEDIUM` only on `CF_DNS_ONLY` or `DIRECT` origins (`J4`).
  4. Suppress `/wp-admin/`, `/wp-content/`, `/wp-includes/`, and `/wp-json/` in `robots.txt` (`J5`), emitting `INFO` if no other sensitive disallow rules remain.
- **Tradeoff**: A single `CRITICAL` on one target in a multi-target batch pulls the batch global score down to that target's score (`min`), ensuring critical exposures can never be masked by clean sibling hosts.

## Item K — Report Splitting, Single Header Dump & Verification Sections
- **Root Cause**: Multi-target Markdown reports truncated at 400k chars mid-finding, and repeating the full HTTP response header block inside every missing-header finding accounted for ~60% of total report size.
- **Detection Decision**:
  1. Split Markdown reports at `100,000` characters on finding/section boundaries (`\n### ` / `\n## `) into `report_<ts>_<n>.md` with an `index.md` (`K1`).
  2. Emit the response header block once per target under the target heading and reference only `Header: <name>` on individual missing-header findings (`K2`).
  3. Include `schema_version`, `confidence`, `cwe`, `cvss`, `evidence_hash`, `first_seen`, `last_seen`, `edge`, and `check_outcome` on every JSON finding (`K3`).
  4. Render per-target `"Verification"` sections separating machine-confirmed findings from `NEEDS MANUAL VERIFICATION` (`K4`).
- **Tradeoff**: Individual missing-header finding snippets show the absent header name rather than duplicating the entire 30-line HTTP response header block on every card.

## Item L — DNS Topology, Grey-Cloud Origin Exposure & Split-Origin Detection
- **Root Cause**: 4 targets (`ffdiamondbd.com`, `codmshopbd.com`, `bdtopupcenter.com`, `vertexbazaar.com`) used Cloudflare nameservers (`*.ns.cloudflare.com`) while their `A` records pointed directly to Hostinger/LiteSpeed/Contabo origin IPs (grey-clouded `CF_DNS_ONLY`). The scanner missed the origin exposure and falsely reported `"WAF detected: Cloudflare"`. Two other targets had dual `A` records across distinct `/16` networks (`185.199.108.153` GitHub Pages + `109.106.255.79` Hostinger).
- **Detection Decision**:
  1. Match `A`/`AAAA` records against Cloudflare's IPv4/IPv6 CIDR blocks (`dns/topology.py`, `L1`).
  2. Classify targets into `CF_PROXIED` (`*.ns.cloudflare.com` + all IPs in CF CIDRs), `CF_DNS_ONLY` (`*.ns.cloudflare.com` + any IP outside CF CIDRs), or `DIRECT` (`L2`).
  3. On `CF_DNS_ONLY`, emit `MEDIUM` `"Origin IP exposed behind Cloudflare (proxy bypassed)"`, set `scan_target = origin_ip` (`L3`), and emit `"Cloudflare DNS only - no WAF in path"` instead of `"WAF detected: Cloudflare"` (`L4`).
  4. When `>=2` `A` records lie in different `/16` networks (and are not all inside Cloudflare anycast), emit `LOW` `"Multiple A records in distinct networks, possible split origin or dangling record"` (`L5`).
- **Tradeoff**: Requires maintaining Cloudflare's published CIDR list in `dns/topology.py` (which changes very rarely).

## Item M — Wildcard DNS Detection & Brute-Force Gate
- **Root Cause**: Zones with wildcard `*.domain` DNS records resolved every dictionary word in `subdomain_wordlist`, flooding reports with nonexistent subdomains.
- **Detection Decision**:
  1. Resolve 2 random 8-character labels (`wc<6hex>.<apex>`) before running dictionary brute-force (`M1`).
  2. If both resolve (`M2`), set `ctx.wildcard_dns = True` and `ctx.brute_force_enabled = False`, emit `INFO` `"Wildcard DNS detected - subdomain brute-force unreliable"`, and skip dictionary brute-force.
- **Tradeoff**: Adds 2 DNS `A` queries per apex domain before dictionary enumeration.
