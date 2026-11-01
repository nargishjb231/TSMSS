# TSMSS 2.0 Ultimate Edition — Android 16+ & Termux Non-Root Compatibility Matrix

TSMSS is architected **Non-Root First** for Android 16+ (`ARM64` / `aarch64`) running inside Termux. Every capability is classified below with its exact technical explanation and non-root alternative.

## Status Classifications
- **SUPPORTED**: Works out-of-the-box in unrooted Termux user-space with zero special Android permissions.
- **PARTIALLY SUPPORTED**: Works in unrooted Termux with documented OS constraints or user-space fallbacks.
- **UNSUPPORTED**: Blocked by the Android kernel/SELinux or Bionic libc ABI on non-root devices; never claimed as available.
- **REQUIRES TESTING**: Optional hardware/companion integrations that depend on whether the user installed the companion APK (`com.termux.api`).

---

## 1. Core Platform & Network Capabilities

| Capability / Feature | Status | Technical Explanation & Non-Root Alternative |
| :--- | :---: | :--- |
| **HTTP/1.1 & TLS 1.2/1.3 Security Auditing** (`httpx`, `ssl`, `socket`) | **SUPPORTED** | Uses standard unprivileged user-space TCP sockets (`AF_INET`/`AF_INET6`, `SOCK_STREAM`). Full certificate chain, SAN, expiry, protocol version, and cipher inspection work without root. |
| **DNS Security Auditing** (`SPF`, `DMARC`, `DKIM`, `CAA`, `DNSSEC`, `AXFR`, `CNAME` Takeover) | **SUPPORTED** | `dnspython` queries recursive resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) directly over UDP/TCP port 53 without relying on `/etc/resolv.conf` (which Android omits outside Termux prefix). |
| **Passive Certificate Transparency (`crt.sh`) & Subdomain Enumeration** | **SUPPORTED** | Queries public HTTPS JSON endpoints in user-space. Discovered subdomains are never automatically treated as in-scope unless `scope.allow_subdomains=true` and not excluded. |
| **Local Source Code Static Analysis (SAST) & Secret Scanning** | **SUPPORTED** | Built-in Python `ast` + pattern analyzer (`modules/source_code.py`) runs 100% offline in pure Python with automatic secret redaction. |
| **Frontend JS Library & Local Lockfile Vulnerability Auditing** | **SUPPORTED** | Inspects remote JS bundles (`modules/dependency_audit.py`) and local manifests (`requirements.txt`, `package.json`, `package-lock.json`, `composer.json`, `go.mod`) against curated CVE advisories. |
| **SQLite Persistence, Scan History & Interrupted Batch Resume** | **SUPPORTED** | Uses Python `sqlite3`. Automatically detects FUSE shared storage (`/sdcard`) and falls back from `WAL` to `DELETE` journal mode if shared-memory mmap locks fail. |
| **FUSE Shared Storage Script Execution** (`/storage/emulated/0`) | **PARTIALLY SUPPORTED** | Android FUSE mounts enforce `noexec` and strip `chmod +x`. Always invoke shell scripts via `bash installer.sh` and Python entrypoints via `python main.py`. |
| **TCP Service Discovery (`connect()` Scan)** | **PARTIALLY SUPPORTED** | Non-root user-space `socket.connect_ex()` and `nmap -sT` work for common ports (`>1024` target ports and standard service ports), but slower than raw SYN scans and subject to per-UID socket descriptor limits (`ulimit -n`). |
| **Android 12–16+ Background Execution (`PhantomProcessList`)** | **PARTIALLY SUPPORTED** | Android caps background child processes (`max_phantom_processes=32`) and throttles background network/CPU without a wake-lock. Run `termux-wake-lock` and use `--profile stealth` or bounded concurrency (`scan.concurrency_targets <= 3`). |
| **PCAPdroid / `mitmproxy` Traffic Inspection** | **PARTIALLY SUPPORTED** | `PCAPdroid` captures traffic without root via Android `VpnService` and exports PCAP/HAR to Termux; `mitmproxy` works for apps trusting user CAs (`network_security_config.xml`). System-wide CA injection into `/system/etc/security/cacerts` requires root on Android 14–16+. |
| **Termux:API Telemetry** (`termux-battery-status`, `termux-notification`, `termux-wake-lock`) | **REQUIRES TESTING** | Requires both `pkg install termux-api` and the matching F-Droid `Termux:API` companion app. TSMSS wraps all calls with short timeouts and runs normally when absent. |
| **Raw Socket / ICMP Ping / SYN Stealth Scan (`nmap -sS`, `tcpdump`)** | **UNSUPPORTED** | Blocked by Android SELinux and missing `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities in unrooted Termux. TSMSS automatically substitutes `connect()` probes and HTTP reachability checks. |
| **Desktop JVM / OCaml Scanners (`OWASP ZAP`, native `Semgrep` CLI)** | **UNSUPPORTED** | Heavy JVM memory footprint (`>1.5 GB`) or OCaml/musl Bionic libc incompatibilities make them unsuitable for stock non-root Termux; replaced by native TSMSS passive, API, and AST modules. |

---

## 2. External CLI Tool Ecosystem Evaluation

| Tool | Official Repository | License | Termux ARM64 Status | Role in TSMSS 2.0 |
| :--- | :--- | :--- | :---: | :--- |
| `python` (`>=3.11`, `3.14`) | `https://github.com/termux/termux-packages` | PSF-2.0 | **SUPPORTED** | Primary runtime engine |
| `openssl` | `https://github.com/openssl/openssl` | Apache-2.0 | **SUPPORTED** | TLS handshake & certificate inspection |
| `dnsutils` (`dig`) | `https://gitlab.isc.org/isc-projects/bind9` | MPL-2.0 | **SUPPORTED** | Auxiliary DNS record verification |
| `nmap` (`-sT` only) | `https://github.com/nmap/nmap` | NPSL | **PARTIALLY SUPPORTED** | Non-root TCP connect scan (`--unprivileged`) |
| `subfinder` | `https://github.com/projectdiscovery/subfinder` | MIT | **SUPPORTED** | Optional passive subdomain discovery (`tools/registry.py`) |
| `dnsx` | `https://github.com/projectdiscovery/dnsx` | MIT | **SUPPORTED** | Optional DNS resolution & wildcard filtering |
| `httpx` (PD CLI) | `https://github.com/projectdiscovery/httpx` | MIT | **SUPPORTED** | Optional HTTP tech probe (`pd-httpx`) |
| `katana` | `https://github.com/projectdiscovery/katana` | MIT | **PARTIALLY SUPPORTED** | Standard HTTP crawl (`-d 2`, headless Chromium disabled) |
| `nuclei` | `https://github.com/projectdiscovery/nuclei` | MIT | **PARTIALLY SUPPORTED** | Safe tags only (`exposure,misconfig,tech,headers,ssl,dns`) |
| `gitleaks` | `https://github.com/gitleaks/gitleaks` | MIT | **SUPPORTED** | Local git repository secret auditing |
| `osv-scanner` | `https://github.com/google/osv-scanner` | Apache-2.0 | **SUPPORTED** | Local lockfile CVE lookup against OSV.dev |
| `pip-audit` | `https://github.com/pypa/pip-audit` | Apache-2.0 | **SUPPORTED** | Python dependency auditing |
