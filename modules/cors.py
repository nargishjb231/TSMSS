"""CORS policy probing with Origin reflection tests."""
from __future__ import annotations

from core.finding import CONFIRMED, HIGH_CONF, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule

EVIL = "https://tsmss-probe.example.net"


class CorsModule(BaseModule):
    name = "cors"
    category = "API Security"

    async def run(self, ctx):
        out = []
        base = await ctx.http.request("GET", ctx.target.url, headers={"Origin": EVIL})
        acao = base.header("access-control-allow-origin")
        acac = base.header("access-control-allow-credentials").lower()
        acam = base.header("access-control-allow-methods")
        acah = base.header("access-control-allow-headers")
        ctx.cors = {"acao": acao, "acac": acac}

        if not acao:
            return [self.make(
                ctx, title="No CORS headers on the primary response",
                severity=INFO,
                description="Cross-origin reads are blocked by default. Expected unless a "
                            "public API is served from this origin.",
                evidence="Origin sent, no Access-Control-Allow-Origin returned",
                detection_method="Origin probe", confidence=CONFIRMED,
                remediation="Add explicit CORS policy only where a public API exists.",
                tags=["cors"])]

        if acao == "*":
            if acac == "true":
                out.append(self.make(
                    ctx, title="Wildcard CORS combined with credentials",
                    severity=MEDIUM, cwe="CWE-942",
                    description="Access-Control-Allow-Origin: * with credentials means any "
                                "origin can read credentialed responses. Combined with "
                                "cookie-based auth this can enable cross-site data theft.",
                    evidence=f"Access-Control-Allow-Origin: {acao}\n"
                             f"Access-Control-Allow-Credentials: {acac}",
                    detection_method="Origin probe", confidence=CONFIRMED,
                    remediation="Echo a validated origin instead of '*', or drop credentials.",
                    tags=["cors"]))
            else:
                out.append(self.make(
                    ctx, title="CORS allows any origin (wildcard, no credentials)",
                    severity=INFO, cwe="CWE-942",
                    description="Public read access from any origin.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    detection_method="Origin probe", confidence=CONFIRMED,
                    remediation="Acceptable for public data; confirm nothing sensitive is exposed.",
                    tags=["cors"]))
        elif acao == EVIL:
            out.append(self.make(
                ctx, title="CORS reflects arbitrary Origin values",
                severity=MEDIUM if acac == "true" else LOW, cwe="CWE-942",
                description=("The origin header is echoed back"
                             + (" with credentials enabled, so any site can read "
                                "authenticated responses." if acac == "true" else ".")),
                evidence=f"Sent Origin: {EVIL}\nReceived Access-Control-Allow-Origin: {acao}",
                detection_method="Origin reflection probe",
                confidence=HIGH_CONF,
                remediation="Validate against an explicit origin allowlist.",
                tags=["cors"]))
        else:
            out.append(self.make(
                ctx, title="CORS allowlist configured",
                severity=INFO, cwe="CWE-942",
                description=f"Returned origin '{acao}' did not match the probe origin.",
                evidence=f"Sent Origin: {EVIL}\nReceived: {acao}",
                detection_method="Origin probe", confidence=CONFIRMED,
                remediation="Verify the allowlist contains no retired or wildcard entries.",
                tags=["cors"]))

        if acam:
            out.append(self.make(
                ctx, title="CORS advertises permitted methods",
                severity=INFO,
                description=f"Access-Control-Allow-Methods: {acam}",
                evidence=f"Access-Control-Allow-Methods: {acam}",
                detection_method="Header inspection", confidence=CONFIRMED,
                remediation="Confirm write methods require authenticated preflight.",
                tags=["cors", "methods"]))
        if acah and "*" in acah:
            out.append(self.make(
                ctx, title="CORS permits arbitrary request headers",
                severity=LOW, cwe="CWE-942",
                description="Wildcard allow-headers relaxes preflight restrictions.",
                evidence=f"Access-Control-Allow-Headers: {acah}",
                detection_method="Header inspection", confidence=CONFIRMED,
                remediation="Enumerate only the headers actually consumed.",
                tags=["cors"]))

        pre = await ctx.http.request("OPTIONS", ctx.target.url, retry=False, headers={
            "Origin": EVIL, "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "authorization,x-tsmss"})
        if pre.status in (200, 204) and pre.header("access-control-allow-origin"):
            out.append(self.make(
                ctx, title="Preflight succeeds from an arbitrary origin",
                severity=LOW if acac != "true" else MEDIUM, cwe="CWE-942",
                description="OPTIONS preflight returned a permissive allow-origin.",
                evidence=f"OPTIONS -> {pre.status}\n" + "\n".join(
                    f"{k}: {v}" for k, v in pre.headers.items() if k.startswith("access-control")),
                detection_method="Preflight probe", confidence=HIGH_CONF,
                remediation="Tie the allowlist to real consumers.",
                tags=["cors", "preflight"]))
        return out