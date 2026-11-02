# Engineering Notes — Detection Decisions & False-Positive Tradeoffs

## Item A — Temp-Dir Hardening & 0-Byte Fetch Guard
- **Root Cause**: On unprivileged Android/Termux, `/tmp` does not exist at the root filesystem level (Termux uses `$PREFIX/tmp`). Any code path or external tool writing temporary artefacts to `/tmp` silently failed, yielding `0`-byte downloads. When two `0`-byte bodies were compared during differential checks, `"" == ""` made every probe look identical or masked failures.
- **Detection Decision**:
  1. Centralize all temporary file and directory allocation in `paths.tmpfile(prefix)` and `paths.tmpdir(prefix)` backed by `tempfile.gettempdir()` with fallback to `$PREFIX/tmp` and `Path.cwd()`.
  2. Execute a mandatory 1-byte write+read+unlink probe (`paths.startup_probe()`) at CLI/menu startup; abort immediately with exit code `3` (`"no writable temp directory"`) if no writable directory exists.
  3. Enforce `validate_response_body()` in `HttpClient.request()` so any `0`-byte body on a body-carrying status (`200`, `403`, `404`, `500`) without an explicit `Content-Length: 0` header is marked as a failed fetch (`ok=False`) and retried rather than compared as an empty string.
- **Tradeoff**: Legitimate HTTP/1.0 servers that close the connection with 0 bytes and omit `Content-Length: 0` are treated as failed fetches rather than valid empty pages, eliminating silent 0-byte differential false positives.
