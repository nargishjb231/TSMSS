# TSMSS 2.0 Ultimate Edition — OWASP Security Coverage & Verification Boundaries

TSMSS 2.0 aligns every security module and finding with four authoritative standards:
- **OWASP Top 10:2025** (`A01:2025` – `A10:2025`)
- **OWASP API Security Top 10:2023** (`API1:2023` – `API10:2023`)
- **OWASP Web Security Testing Guide (WSTG) v4.2** (`WSTG-INFO`, `WSTG-CONF`, `WSTG-IDNT`, `WSTG-ATHN`, `WSTG-ATHZ`, `WSTG-SESS`, `WSTG-INPV`, `WSTG-ERRH`, `WSTG-CRYP`, `WSTG-BUSL`, `WSTG-CLNT`, `WSTG-APIT`)
- **OWASP Application Security Verification Standard (ASVS) v5.0**

---

## 1. Automated vs. Manual Verification Policy

TSMSS strictly separates **deterministic, evidence-backed observations** from **heuristic indicators that require manual human verification**:

| Verification Tier | Meaning | Report Placement |
| :--- | :--- | :--- |
| `CONFIRMED` | Positive, reproducible protocol/configuration fact backed by raw HTTP/TLS/DNS/AST evidence (e.g., missing `Strict-Transport-Security`, reflected `Origin` with `Access-Control-Allow-Credentials: true`, exposed `.git/HEAD`, `eval()` in local Python AST). | Primary **Confirmed & Strong-Evidence Findings** section |
| `STRONG EVIDENCE` | High-confidence signature match backed by captured response body/header snippet (e.g., DBMS SQL error signature on differential probe, vulnerable JS library version, sensitive token written to `localStorage`). | Primary **Confirmed & Strong-Evidence Findings** section |
| `POTENTIAL` | Moderate-confidence anomaly requiring analyst review (e.g., differential status/length shift, unpinned dependency manifest entry). | Separated **Needs Manual Verification & Potential Indicators** container |
| `NEEDS MANUAL VERIFICATION` | Passive architectural or parameter indicator that cannot be confirmed without multi-account credentials or business-logic context (e.g., BOLA/IDOR numeric object-ID routes, BFLA admin route references, DOM source/sink co-occurrence, pagination/webhook parameters). | Separated **Needs Manual Verification & Potential Indicators** container |

> **Important**: Server version banners, `X-Powered-By` headers, and unverified parameter-name heuristics (`id=`, `url=`, `file=`) are **never** marked `CONFIRMED`.

---

## 2. Module-to-OWASP Coverage Map

| TSMSS Module | Primary File | OWASP Top 10:2025 | OWASP API Top 10:2023 | WSTG v4.2 IDs |
| :--- | :--- | :--- | :--- | :--- |
| **HTTP Security** | `modules/http_security.py` | `A02:2025` Security Misconfiguration | `API8:2023` | `WSTG-CONF-06`, `WSTG-CONF-07`, `WSTG-CLNT-09` |
| **TLS / SSL Security** | `modules/ssl_tls.py` | `A04:2025` Cryptographic Failures | `API8:2023` | `WSTG-CRYP-01`, `WSTG-CRYP-02`, `WSTG-CRYP-03` |
| **DNS Security** | `modules/dns_security.py` | `A02:2025` Security Misconfiguration | — | `WSTG-CONF-10`, `WSTG-INFO-06` |
| **Reconnaissance & Client-Side** | `modules/reconnaissance.py` | `A02:2025`, `A05:2025`, `A08:2025` | `API9:2023` | `WSTG-INFO-03`, `WSTG-BUSL-08`, `WSTG-CLNT-01`, `WSTG-CLNT-12` |
| **Cookie Security** | `modules/cookies.py` | `A07:2025` Authentication Failures | `API2:2023` | `WSTG-SESS-02`, `WSTG-SESS-03` |
| **CORS Security** | `modules/cors.py` | `A02:2025` Security Misconfiguration | `API8:2023` | `WSTG-CLNT-07` |
| **Authentication** | `modules/authentication.py` | `A07:2025` Authentication Failures | `API2:2023` | `WSTG-ATHN-01`, `WSTG-SESS-05` |
| **Authorization** | `modules/authorization.py` | `A01:2025` Broken Access Control | `API1:2023`, `API5:2023` | `WSTG-ATHZ-01`, `WSTG-ATHZ-02`, `WSTG-ATHZ-04` |
| **Information Disclosure** | `modules/information_disclosure.py` | `A02:2025`, `A10:2025` | `API8:2023`, `API9:2023` | `WSTG-INFO-05`, `WSTG-CONF-04`, `WSTG-ERRH-01` |
| **API Security** | `modules/api_security.py` | `A01:2025`, `A02:2025`, `A06:2025` | `API1:2023` – `API10:2023` | `WSTG-APIT-01`, `WSTG-ATHZ-04`, `WSTG-BUSL-01` |
| **Vulnerability Indicators** | `modules/vulnerability_indicators.py` | `A01:2025`, `A05:2025`, `A08:2025`, `A10:2025` | `API7:2023`, `API8:2023` | `WSTG-INPV-01` – `WSTG-INPV-19` |
| **Dependency Audit** | `modules/dependency_audit.py` | `A03:2025` Software Supply Chain | — | `WSTG-INFO-08` |
| **Source Code Security** | `modules/source_code.py` | `A02:2025`, `A04:2025`, `A05:2025`, `A08:2025` | — | `WSTG-CRYP-04`, `WSTG-INPV-12` |
| **Infrastructure** | `modules/infrastructure.py` | `A02:2025` Security Misconfiguration | — | `WSTG-INFO-02`, `WSTG-INFO-04` |
