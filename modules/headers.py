"""Header rule engine backed by config/rules.yaml."""
from __future__ import annotations

from core.finding import CONFIRMED, Finding
from modules.base import BaseModule

BUILTIN = {
    "content-security-policy": dict(
        severity="MEDIUM", cwe="CWE-693",
        title="Content-Security-Policy header absent",
        description="No CSP is returned, so the browser has no declarative allowlist to "
                    "restrict script, style and frame sources. This widens the impact of any "
                    "markup-injection flaw.",
        remediation="Deploy a CSP starting in Report-Only, then enforce with "
                    "script-src 'self' plus nonces or hashes."),
    "x-content-type-options": dict(
        severity="LOW", cwe="CWE-693",
        title="X-Content-Type-Options missing (MIME sniffing enabled)",
        description="Without 'nosniff', browsers may reinterpret a response body as a "
                    "different content type.",
        remediation="Send: X-Content-Type-Options: nosniff"),
    "referrer-policy": dict(
        severity="LOW", cwe="CWE-200",
        title="Referrer-Policy header absent",
        description="Full URLs, including query strings, may leak to third parties via the "
                    "Referer header.",
        remediation="Send: Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions-policy": dict(
        severity="LOW", cwe="CWE-693",
        title="Permissions-Policy header absent",
        description="Browser feature access (camera, geolocation, microphone) is unrestricted "
                    "for embedded content.",
        remediation="Send an explicit Permissions-Policy denying unused features."),
    "cross-origin-opener-policy": dict(
        severity="LOW", cwe="CWE-693",
        title="Cross-Origin-Opener-Policy absent",
        description="No process isolation between the page and opened cross-origin windows.",
        remediation="Send: Cross-Origin-Opener-Policy: same-origin"),
}

EXPECTED_PRESENT = {"content-security-policy", "x-content-type-options",
                    "referrer-policy", "permissions-policy", "cross-origin-opener-policy"}


class HeaderModule(BaseModule):
    """Shared helper: check presence of a header, honouring rule overrides."""
    name = "headers"
    category = "HTTP Security"

    def __init__(self, rules: dict | None = None):
        self.rules = rules or {}

    def rule(self, header: str) -> dict | None:
        return (self.rules.get("headers") or {}).get(header) or BUILTIN.get(header)

    def missing_finding(self, ctx, resp, header: str) -> Finding | None:
        rule = self.rule(header)
        if not rule:
            return None
        return self.make(
            ctx, title=rule["title"], severity=rule["severity"], cwe=rule.get("cwe"),
            description=rule["description"],
            evidence=f"Response headers for {resp.url}:\n" + _dump(resp.headers),
            detection_method="Response header inspection",
            confidence=CONFIRMED, remediation=rule.get("remediation", ""),
            tags=["headers", header],
        ).downgrade_if_heuristic("missing_header")


def _dump(headers: dict[str, str]) -> str:
    if not headers:
        return "(none)"
    return "\n".join(f"{k}: {v}" for k, v in sorted(headers.items()))