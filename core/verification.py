"""Finding verification engine, OWASP/WSTG enrichment, and baseline fingerprinting."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

VERIFICATION_STATES = (
    "CONFIRMED",
    "STRONG EVIDENCE",
    "POTENTIAL",
    "NEEDS MANUAL VERIFICATION",
)

# Maps category / CWE / keywords to OWASP Top 10:2025, WSTG v4.2, impact, and FP notes.
_CATEGORY_DEFAULTS: dict[str, dict[str, str]] = {
    "Reconnaissance": {
        "owasp": "OWASP Top 10:2025 A02 (Security Misconfiguration)",
        "wstg": "WSTG-INFO-03 / WSTG-INFO-05 / WSTG-CLNT-01",
        "impact": "Exposes application structure, endpoints, or client-side source artifacts to attackers.",
        "fp_notes": "Publicly intended routes in robots.txt or sitemap.xml are informational unless sensitive paths are exposed.",
    },
    "HTTP Security": {
        "owasp": "OWASP Top 10:2025 A02 (Security Misconfiguration)",
        "wstg": "WSTG-CONF-06 / WSTG-CONF-07 / WSTG-CLNT-09",
        "impact": "Weakens browser-enforced defense-in-depth against framing, MIME sniffing, or downgrade attacks.",
        "fp_notes": "Missing security headers are configuration weaknesses, not direct proof of account compromise.",
    },
    "SSL/TLS Security": {
        "owasp": "OWASP Top 10:2025 A04 (Cryptographic Failures)",
        "wstg": "WSTG-CRYP-01",
        "impact": "Weak transport encryption or invalid certificates allow interception or MITM downgrade attacks.",
        "fp_notes": "CDN edge certificates may differ from origin server TLS configurations.",
    },
    "DNS Security": {
        "owasp": "OWASP Top 10:2025 A02 (Security Misconfiguration)",
        "wstg": "WSTG-INFO-02 / WSTG-CONF-10",
        "impact": "Missing mail authentication (SPF/DMARC) or dangling CNAMEs enable domain spoofing or subdomain takeover.",
        "fp_notes": "Domains that never send email still benefit from a reject-all SPF/DMARC policy.",
    },
    "Cookie Security": {
        "owasp": "OWASP Top 10:2025 A07 (Authentication Failures)",
        "wstg": "WSTG-SESS-02",
        "impact": "Cookies lacking Secure, HttpOnly, or SameSite flags are exposed to script access or cross-site transmission.",
        "fp_notes": "Non-sensitive UI preference or analytics cookies have lower impact than session identifiers.",
    },
    "CORS Security": {
        "owasp": "OWASP Top 10:2025 A02 (Security Misconfiguration) / API8:2023",
        "wstg": "WSTG-CLNT-07",
        "impact": "Overly permissive CORS with credentials allows untrusted origins to read authenticated responses.",
        "fp_notes": "Wildcard ACAO (*) without Access-Control-Allow-Credentials is safe for intentionally public resources.",
    },
    "Information Disclosure": {
        "owasp": "OWASP Top 10:2025 A02 (Security Misconfiguration)",
        "wstg": "WSTG-INFO-02 / WSTG-CONF-04",
        "impact": "Leaks server versions, environment variables, repository metadata, or internal debug configuration.",
        "fp_notes": "Version banners alone do not prove an unpatched CVE due to OS distribution backporting.",
    },
    "Framework Auditing": {
        "owasp": "OWASP Top 10:2025 A02 / A03 (Software Supply Chain Failures)",
        "wstg": "WSTG-INFO-08 / WSTG-CONF-01",
        "impact": "Framework-specific debug endpoints or outdated frontend libraries increase attack surface.",
        "fp_notes": "Verify that the vulnerable library function is reachable in the application context.",
    },
    "API Security": {
        "owasp": "OWASP API Security Top 10:2023 (API1-API10)",
        "wstg": "WSTG-APIT-01",
        "impact": "Exposed schemas, missing rate limits, or object-level authorization gaps risk API data exposure or abuse.",
        "fp_notes": "Public API documentation may be intentional; authorization checks require multi-account verification.",
    },
    "Authentication & Authorization": {
        "owasp": "OWASP Top 10:2025 A01 (Broken Access Control) / A07 (Authentication Failures)",
        "wstg": "WSTG-ATHN-01 / WSTG-ATHZ-02 / WSTG-SESS-01",
        "impact": "Weak authentication transport, missing CSRF tokens, or IDOR surfaces risk unauthorized account actions.",
        "fp_notes": "A parameter ID or HTTP 200 status alone does not prove IDOR/BOLA; verify with two distinct test accounts.",
    },
    "Vulnerability": {
        "owasp": "OWASP Top 10:2025 A05 (Injection)",
        "wstg": "WSTG-INPV-01 / WSTG-INPV-05 / WSTG-INPV-11",
        "impact": "Input handling or reflection anomalies may allow script injection, query manipulation, or server-side requests.",
        "fp_notes": "HTTP 500 errors or WAF block pages do not prove injection; confirm in a controlled test environment.",
    },
    "Source Code Security": {
        "owasp": "OWASP Top 10:2025 A04 (Cryptographic Failures) / A05 (Injection) / ASVS V2-V6",
        "wstg": "WSTG-CRYP-04 / WSTG-INPV-05",
        "impact": "Hardcoded secrets, weak hashes, or unsafe execution sinks in source code introduce exploitable flaws.",
        "fp_notes": "Verify whether matched files belong to production code paths rather than mock test fixtures.",
    },
    "Dependency Security": {
        "owasp": "OWASP Top 10:2025 A03 (Software Supply Chain Failures)",
        "wstg": "WSTG-CONF-01",
        "impact": "Known vulnerable third-party packages expose the application to publicly documented CVEs.",
        "fp_notes": "Confirm whether the vulnerable function or feature flag in the dependency is used by the application.",
    },
    "Infrastructure": {
        "owasp": "OWASP Top 10:2025 A02 (Security Misconfiguration)",
        "wstg": "WSTG-CONF-03 / WSTG-INFO-04",
        "impact": "Exposed administrative/database ports or internal IP disclosure assist network-level reconnaissance.",
        "fp_notes": "Filtered or CDN-proxied ports may reflect edge proxy listeners rather than the origin server.",
    },
}

_CWE_WSTG_OVERRIDES: dict[str, tuple[str, str]] = {
    "CWE-79": ("OWASP Top 10:2025 A05 (Injection - XSS)", "WSTG-INPV-01 / WSTG-CLNT-01"),
    "CWE-89": ("OWASP Top 10:2025 A05 (Injection - SQLi)", "WSTG-INPV-05"),
    "CWE-78": ("OWASP Top 10:2025 A05 (Injection - OS Command)", "WSTG-INPV-12"),
    "CWE-90": ("OWASP Top 10:2025 A05 (Injection - LDAP)", "WSTG-INPV-06"),
    "CWE-943": ("OWASP Top 10:2025 A05 (Injection - NoSQL)", "WSTG-INPV-05"),
    "CWE-611": ("OWASP Top 10:2025 A02 / A05 (XXE)", "WSTG-INPV-07"),
    "CWE-1336": ("OWASP Top 10:2025 A05 (Injection - SSTI)", "WSTG-INPV-18"),
    "CWE-918": ("OWASP Top 10:2025 A01 / API7:2023 (SSRF)", "WSTG-INPV-19"),
    "CWE-22": ("OWASP Top 10:2025 A01 (Broken Access Control - Path Traversal)", "WSTG-ATHZ-01"),
    "CWE-98": ("OWASP Top 10:2025 A05 (LFI/RFI)", "WSTG-INPV-11"),
    "CWE-502": ("OWASP Top 10:2025 A08 (Software or Data Integrity Failures - Deserialization)", "WSTG-INPV-16"),
    "CWE-601": ("OWASP Top 10:2025 A01 (Open Redirect)", "WSTG-CLNT-04"),
    "CWE-639": ("OWASP Top 10:2025 A01 / API1:2023 (BOLA / IDOR)", "WSTG-ATHZ-04"),
    "CWE-285": ("OWASP Top 10:2025 A01 / API5:2023 (Broken Authorization)", "WSTG-ATHZ-02"),
    "CWE-915": ("OWASP API Security Top 10:2023 API3:2023 (BOPLA / Mass Assignment)", "WSTG-APIT-01"),
    "CWE-770": ("OWASP API Security Top 10:2023 API4:2023 (Unrestricted Resource Consumption)", "WSTG-BUSL-05"),
    "CWE-352": ("OWASP Top 10:2025 A01 / A07 (Cross-Site Request Forgery)", "WSTG-SESS-05"),
    "CWE-347": ("OWASP Top 10:2025 A04 / A07 (JWT Cryptographic Verification)", "WSTG-SESS-10"),
    "CWE-798": ("OWASP Top 10:2025 A07 / MASVS-STORAGE (Hardcoded Credentials)", "WSTG-ATHN-01"),
    "CWE-327": ("OWASP Top 10:2025 A04 / MASVS-CRYPTO (Broken Cryptographic Algorithm)", "WSTG-CRYP-04"),
    "CWE-353": ("OWASP Top 10:2025 A08 (Missing Subresource Integrity)", "WSTG-CLNT-13"),
}

# Patterns that must never be marked CONFIRMED per Section 8 rules.
_NEVER_CONFIRMED_PATTERNS = re.compile(
    r"(?i)(possible\s+idor|parameter\s+id|boolean-based\s+sqli\s+indicator|candidate\s+ssrf"
    r"|role\s+or\s+permission\s+fields|server\s+header\s+discloses\s+version|technology\s+disclosed"
    r"|indicator|heuristic|manual\s+verification)"
)


def map_confidence_to_verification(confidence: str, title: str = "", evidence: str = "") -> str:
    """Determine the 4-tier verification status from confidence and evidence."""
    conf = (confidence or "").upper()
    if _NEVER_CONFIRMED_PATTERNS.search(title or ""):
        if conf in ("CONFIRMED", "HIGH CONFIDENCE", "STRONG EVIDENCE"):
            return "POTENTIAL" if "idor" in (title or "").lower() else "STRONG EVIDENCE"
        return "NEEDS MANUAL VERIFICATION"
    if not (evidence or "").strip():
        return "NEEDS MANUAL VERIFICATION"
    if conf == "CONFIRMED":
        return "CONFIRMED"
    if conf in ("STRONG EVIDENCE", "HIGH CONFIDENCE"):
        return "STRONG EVIDENCE"
    if conf in ("POTENTIAL", "MEDIUM CONFIDENCE"):
        return "POTENTIAL"
    return "NEEDS MANUAL VERIFICATION"


def enrich_finding(finding: Any) -> Any:
    """Populate OWASP, WSTG, endpoint, impact, false_positive_notes, and 4-tier verification_status."""
    cat_info = _CATEGORY_DEFAULTS.get(finding.category, _CATEGORY_DEFAULTS["HTTP Security"])
    if finding.cwe and finding.cwe in _CWE_WSTG_OVERRIDES:
        owasp_ref, wstg_ref = _CWE_WSTG_OVERRIDES[finding.cwe]
    else:
        owasp_ref, wstg_ref = cat_info["owasp"], cat_info["wstg"]

    if not getattr(finding, "owasp_reference", ""):
        api_tags = [t for t in getattr(finding, "tags", []) if isinstance(t, str) and t.upper().startswith("API") and ":2023" in t]
        if api_tags and any(a not in owasp_ref for a in api_tags):
            owasp_ref = f"{owasp_ref} [{', '.join(api_tags)}]"
        finding.owasp_reference = owasp_ref
    if not getattr(finding, "wstg_reference", ""):
        finding.wstg_reference = wstg_ref
    if not getattr(finding, "impact", ""):
        finding.impact = cat_info["impact"]
    if not getattr(finding, "false_positive_notes", ""):
        finding.false_positive_notes = cat_info["fp_notes"]
    if not getattr(finding, "endpoint", ""):
        finding.endpoint = finding.url or finding.target
    if not getattr(finding, "test_id", ""):
        mod_prefix = (finding.module or finding.category or "GEN")[:5].upper().replace(" ", "")
        finding.test_id = f"TSMSS-{mod_prefix}-{finding.cwe or '001'}"

    # Guard against marking heuristic/banner/IDOR findings as CONFIRMED
    if _NEVER_CONFIRMED_PATTERNS.search(finding.title or "") and finding.confidence == "CONFIRMED":
        finding.confidence = "HIGH CONFIDENCE"

    if not finding.verification_status or finding.verification_status in (
        "UNVERIFIED", "AUTO-VERIFIED", "MANUAL-REVIEW-REQUIRED"
    ):
        finding.verification_status = map_confidence_to_verification(
            finding.confidence, finding.title, finding.evidence
        )
    return finding


# ---- Baseline Support (Item 13) -----------------------------------------
def save_baseline(path: Path | str, findings: Iterable[Any]) -> Path:
    """Write deterministic baseline JSON keyed by (module, target, check, evidence_digest)."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[tuple[str, str, str, str]] = set()
    entries: list[dict[str, str]] = []
    for f in findings:
        fp = f.fingerprint()
        if fp in seen:
            continue
        seen.add(fp)
        entries.append(f.fingerprint_dict())
    entries.sort(key=lambda e: (e["target"], e["module"], e["check"], e["evidence_digest"]))
    payload = {
        "schema": "tsmss-baseline/1.0",
        "count": len(entries),
        "entries": entries,
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def load_baseline(path: Path | str) -> set[tuple[str, str, str, str]]:
    """Load exact 4-tuple fingerprints (module, target, check, evidence_digest) from baseline JSON."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Baseline file not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    raw_entries = data.get("entries", []) if isinstance(data, dict) else []
    out: set[tuple[str, str, str, str]] = set()
    for item in raw_entries:
        if isinstance(item, dict):
            out.add((
                str(item.get("module", "")),
                str(item.get("target", "")),
                str(item.get("check", "")),
                str(item.get("evidence_digest", "")),
            ))
    return out


def filter_by_baseline(findings: Iterable[Any], baseline_fingerprints: set[tuple[str, str, str, str]]) -> tuple[list[Any], int]:
    """Return (remaining_findings, suppressed_count) using exact 4-tuple match."""
    kept: list[Any] = []
    suppressed = 0
    for f in findings:
        if f.fingerprint() in baseline_fingerprints:
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed
