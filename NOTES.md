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
