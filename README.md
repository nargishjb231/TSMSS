# TSMSS — Termux Super Master Security Scanner (v2.0 Ultimate Edition)

**TSMSS 2.0 Ultimate Edition** is an evidence-based, non-destructive mobile security auditing and bug bounty research platform engineered **Non-Root First** for **Android 16+ / Termux (`ARM64`)** and cross-platform Python `>=3.11` (`3.14` target).

> **Authorized Use Only**: TSMSS is strictly for testing targets and source repositories you own or have explicit written authorization to assess. It probes configurations, headers, TLS/DNS posture, API schemas, and passive/safe differential indicators — it **never** executes destructive payloads, brute-force attacks, or denial-of-service traffic.

---

## Key Capabilities

1. **14 OWASP-Aligned Security Modules**:
   - `http_security` — Security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP/COEP/CORP`), unsafe HTTP methods, and HTTPS enforcement (gated on `ssl_tls` being enabled).
   - `ssl_tls` — TLS protocol versions (`TLSv1.0`/`1.1`/`1.2`/`1.3`), weak ciphers, certificate chain validation, SAN mismatch, and expiry checks.
   - `dns_security` — `SPF`, `DMARC`, `DKIM`, `CAA`, `DNSSEC`, open zone transfer (`AXFR`), and dangling `CNAME` subdomain takeover checks.
   - `reconnaissance` — Passive `robots.txt` sensitive path analysis, `sitemap.xml` inventory, `<input type="file">` upload configuration checks, missing Subresource Integrity (`SRI`), exposed `.js.map` source maps, client-side DOM source/sink co-occurrence, and Web Storage token sinks.
   - `cookie_security` — Multi-header `Set-Cookie` parsing (`Fetched.get_all`) for `Secure`, `HttpOnly`, `SameSite`, and `__Host-`/`__Secure-` prefix rules.
   - `cors` — Origin reflection, `null` origin trust, and `Access-Control-Allow-Credentials: true` misconfigurations.
   - `authentication` — Cleartext login forms, missing CSRF tokens on state-changing forms (with SPA false-positive filtering), and session fixation indicators.
   - `authorization` — Exposed administrative endpoints and passive BOLA/IDOR object-ID parameter indicators.
   - `information_disclosure` — Exposed `.env`, `.git/HEAD`, backup archives (strictly anchored on content-type and archive magic bytes), stack traces, and server banners.
   - `api_security` — Coverage across **OWASP API Security Top 10:2023 (`API1:2023`–`API10:2023`)**, OpenAPI/Swagger/GraphQL discovery, BOPLA sensitive JSON properties, pagination parameters, webhook SSRF surfaces, and rate-limit header inspection.
   - `vulnerability_indicators` — Non-destructive passive and safe differential indicators for reflected XSS (distinguishing raw reflection from HTML-encoded output), SQL/NoSQL error leakage, SSTI, open redirects, LFI/RFI, XXE, CRLF, host-header injection, and deserialization signatures.
   - `dependency_audit` — Remote JavaScript library CVE matching (`jQuery`, `Lodash`, `Angular`, `Bootstrap`, `Moment.js`, `DOMPurify`, `Handlebars`) plus local manifest/lockfile auditing (`requirements.txt`, `package.json`, `package-lock.json`, `composer.json`, `go.mod`).
   - `source_code` — Offline Python `ast` static analyzer (`eval`/`exec`, `shell=True`, `pickle.loads`, unsafe `yaml.load`, weak `md5`/`sha1` hashes, SQL string interpolation) + multi-language secret/config scanner with automatic credential redaction.
   - `infrastructure` — Non-root TCP `connect()` port probing, `security.txt` (`RFC 9116`), and reverse-proxy/CDN fingerprinting.

2. **4-Tier Evidence & Verification Engine**:
   - Every finding is classified as `CONFIRMED`, `STRONG EVIDENCE`, `POTENTIAL`, or `NEEDS MANUAL VERIFICATION` and enriched with **OWASP Top 10:2025**, **OWASP API Top 10:2023**, **WSTG v4.2**, **CWE**, **CVE**, impact, remediation, and false-positive notes.
   - Heuristic indicators (`NEEDS MANUAL VERIFICATION` and `POTENTIAL`) are visually separated from confirmed findings in HTML and Markdown reports.

3. **Hardened HTTP Client, Baselines, Diffing & Resumption**:
   - **Retry Policy**: Bounded exponential backoff with jitter on `408`, `429`, `5xx`, and connection resets, honouring `Retry-After` (delta-seconds and HTTP-date). Never retries other `4xx` responses.
   - **Baselines**: `--write-baseline file.json` and `--baseline file.json` using exact 4-tuple fingerprints `(module, target, check, evidence_digest)`.
   - **Scan Diffing**: `--diff previous.json` renders `new`, `fixed`, and `still_open` findings per target.
   - **SQLite Resume**: `--resume <scan_id>` picks up unfinished (`pending`/`running`) targets from SQLite under the same `scan_id`.

4. **8 Report Formats + Offline AI Upload Package**:
   - Generates **HTML** (100% inline CSS/JS, sortable columns, sticky filter bar, severity/verification chips, per-target tabs), **JSON** (validated against `schemas/tsmss-report-v2.schema.json`), **JSONL**, **Markdown**, **TXT**, **CSV**, **SARIF v2.1.0**, and an offline **AI Upload Package** (`reports/ai_packages/<scan_id>/` with redacted JSON, JSONL, context-window chunks, and `AI_ANALYSIS_PROMPT.md`).

---

## Installation (Termux / Android 16+ Non-Root & Desktop Linux/macOS/Windows)

> **FUSE Mount Note**: On Android shared storage (`/sdcard`), the filesystem is mounted `noexec`. Always invoke shell scripts with `bash script.sh` (never `./script.sh`).

### Termux (Android ARM64 — Non-Root)
```bash
bash installer.sh
python main.py
```

### Standard Python Virtual Environment
```bash
python -m venv .venv
# Linux / Termux / macOS:
source .venv/bin/activate
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
python tests/selftest.py
```

---

## Usage & CLI Subcommands

TSMSS provides both an interactive **16-Option Mobile Terminal UI** (`python main.py`) and full CLI subcommands (`scan`, `list`, `report`, `config`) while keeping all legacy flags working.

### 1. Interactive 16-Option Mobile Terminal UI
```bash
python main.py
# Force plain-text accessible mode for narrow or non-ANSI terminals:
python main.py --plain-ui
```
Menu options:
1. Quick Scan (`--profile quick`)
2. Full Authorized Scan (`--profile standard`)
3. Passive Recon Only (`--profile passive`)
4. API Security Audit (`api_security`, `cors`, `http_security`, `authentication`, `authorization`)
5. Web Application Security Audit
6. Source Code Security Audit (`modules/source_code.py`)
7. Dependency Vulnerability Scan (`modules/dependency_audit.py`)
8. Multi-Target Batch Scan (`targets.txt`)
9. Custom Module Selection
10. Resume Interrupted Scan (`--resume <scan_id>`)
11. View Scan History (with search & diffing)
12. Generate / Export Reports (`HTML`, `JSON`, `JSONL`, `MD`, `TXT`, `CSV`, `SARIF`, `AI`)
13. AI Report Package Builder (`reports/ai_packages/<scan_id>/`)
14. Scope & Rate-Limit Settings (with validation & rollback)
15. Tool & Termux Compatibility Check (local device diagnostics only)
16. Help / Legal / Documentation

### 2. `scan` Subcommand (Single, Batch, Profiles, Baselines, Diff & Resume)
```bash
# Single target scan with a preset profile (quick | standard | passive | stealth | deep | source)
python main.py scan -u https://example.com --profile quick

# Batch scan from targets.txt and write a baseline file
python main.py scan -b targets.txt --write-baseline baseline.json

# Suppress known findings from a baseline and diff against a previous JSON report
python main.py scan -b targets.txt --baseline baseline.json --diff reports/json/previous.json

# Resume an interrupted batch scan from SQLite
python main.py scan --resume <scan_id>

# Audit a local source code directory and dependency manifests offline
python main.py scan --source-dir ./my-app
```

### 3. `list` Subcommand (Validate & Preview Target List)
```bash
python main.py list targets.txt
```

### 4. `report` Subcommand (Export Any Format or Diff Past Scans)
```bash
# Export specific format (html | json | jsonl | md | txt | csv | sarif | ai | all)
python main.py report <scan_id> --format sarif
python main.py report <scan_id> --format ai

# Diff a stored scan against a previous JSON report
python main.py report <scan_id> --diff reports/json/previous.json
```

### 5. `config` Subcommand (Inspect, Validate & Update Settings)
```bash
python main.py config --show
python main.py config --validate
python main.py config --get scan.batch_size
python main.py config --set modules.disabled=ssl_tls,dns_security
```

---

## Testing & Verification

Run the built-in self-test and the full unit/integration test suite:
```bash
python tests/selftest.py
python -m unittest discover -s tests -p "test_*.py" -v
```

See also:
- [Android 16+ & Termux Compatibility Matrix](docs/COMPATIBILITY_MATRIX.md)
- [OWASP Top 10:2025 / API Top 10:2023 / WSTG v4.2 Coverage](docs/OWASP_COVERAGE.md)
- [AI Report v2.0 JSON Schema](schemas/tsmss-report-v2.schema.json)
