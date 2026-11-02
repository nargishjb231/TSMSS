"""HTTP configuration: headers, methods, transport, disclosure, redirects, clickjacking."""
from __future__ import annotations

import re

from core.finding import CONFIRMED, HIGH_CONF, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule
from modules.headers import EXPECTED_PRESENT, HeaderModule, _dump
from net.client import make_unreachable_finding
from probe.challenge import EDGE_BANNER, detect_challenge, extract_meta_csp

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PROBE_METHODS = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "DEBUG"]

SERVER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator",
                  "x-drupal-cache", "x-runtime", "x-rack-cache")

def _header_tokens(resp, name):
    """Split a possibly repeated header into lowercased, de-duplicated tokens."""
    out = []
    for raw in resp.get_all(name):
        for chunk in raw.split(","):
            tok = chunk.strip().lower()
            if tok and tok not in out:
                out.append(tok)
    return out


VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)*)")


class HttpSecurityModule(BaseModule):
    name = "http_security"
    category = "HTTP Security"

    def __init__(self, rules: dict | None = None):
        self.header_check = HeaderModule(rules)

    async def run(self, ctx) -> list:
        out: list = []
        base = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not base.ok and base.status == 0:
            ctx.http_unreachable = base.error or "HTTP origin unreachable"
            out.append(make_unreachable_finding(ctx.target.url, ctx.http_unreachable))
            return out
        ctx.homepage = base
        is_chal, chal_prov = detect_challenge(base.status, base.headers, base.body)
        if getattr(base, "edge_challenged", False) or is_chal:
            ctx.edge_challenged = True
            ctx.edge_banner = EDGE_BANNER
            return self._handle_edge_challenge(ctx, base, chal_prov or getattr(base, "challenge_provider", "Edge"))
        out += await self._headers(ctx, base)
        out += await self._xcto(ctx, base)
        out += await self._transport(ctx, base)
        out += await self._disclosure(ctx, base)
        out += await self._methods(ctx)
        out += await self._clickjacking(ctx, base)
        out += await self._cache_control(ctx, base)
        return out

    def _handle_edge_challenge(self, ctx, resp, provider: str) -> list:
        """E3: When only an edge/WAF challenge page is returned, suppress app-header claims."""
        found = []
        meta_csp = extract_meta_csp(resp.body)
        hdr_csp = resp.header("content-security-policy")
        csp_src = "meta" if meta_csp else ("header" if hdr_csp else "")
        evidence_lines = [
            f"Banner: {EDGE_BANNER}",
            f"Provider: {provider or 'WAF/CDN'}",
            f"Status: {resp.status}",
            "Note: describes edge response (application origin not observed)",
        ]
        if meta_csp:
            evidence_lines.append(f"csp_source: meta\nMeta CSP: {meta_csp[:300]}")
        elif hdr_csp:
            evidence_lines.append(f"csp_source: header\nHeader CSP: {hdr_csp[:300]}")

        f_edge = self.make(
            ctx,
            title=f"{EDGE_BANNER} — {provider or 'WAF'} interstitial blocked origin inspection",
            severity=INFO,
            cwe="CWE-693",
            description=(
                "The target returned a bot/WAF challenge interstitial on all attempts "
                "(including browser User-Agent retry). Application headers cannot be "
                "verified; this finding describes edge response behavior only."
            ),
            evidence="\n".join(evidence_lines),
            detection_method="WAF/CDN challenge detection",
            confidence=CONFIRMED,
            remediation="Allowlist the scanner IP at the WAF/CDN or test origin directly if authorized.",
            tags=["edge", "challenge", "waf"],
        )
        f_edge.edge = True
        f_edge.csp_source = csp_src
        found.append(f_edge)

        # Only HSTS if explicitly present on the 403/503 edge response is evaluated as an edge finding
        hsts = resp.header("strict-transport-security")
        if hsts and "max-age=0" in hsts.lower():
            f_hsts = self.make(
                ctx,
                title="Edge Strict-Transport-Security sets max-age=0 (describes edge response)",
                severity=MEDIUM,
                cwe="CWE-319",
                description="The edge challenge response disables HSTS via max-age=0 (describes edge response).",
                evidence=f"Strict-Transport-Security: {hsts}\ndescribes edge response",
                detection_method="Edge header value validation",
                confidence=CONFIRMED,
                remediation="Configure a positive HSTS max-age on the CDN/edge.",
                tags=["edge", "headers", "hsts"],
            )
            f_hsts.edge = True
            found.append(f_hsts)
        return found

    async def _headers(self, ctx, resp):
        found = []
        for header in EXPECTED_PRESENT:
            if header in resp.headers:
                continue
            f = self.header_check.missing_finding(ctx, resp, header)
            if f:
                found.append(f)
        # Present-but-weak values
        csp = resp.header("content-security-policy")
        if csp:
            weak = [d for d in ("unsafe-inline", "unsafe-eval", "*") if d in csp]
            if weak:
                found.append(self.make(
                    ctx, title="Content-Security-Policy permits weak sources",
                    severity=MEDIUM, cwe="CWE-693",
                    description=f"The CSP includes permissive directives: {', '.join(weak)}.",
                    evidence=f"Content-Security-Policy: {csp[:600]}",
                    detection_method="CSP directive inspection",
                    confidence=CONFIRMED,
                    remediation="Remove 'unsafe-inline'/'unsafe-eval' in favour of nonces or "
                                "hashes; avoid wildcard sources.",
                    tags=["headers", "csp"]))
        xfo = _header_tokens(resp, "x-frame-options")
        bad_xfo = [t for t in xfo if t not in ("deny", "sameorigin")]
        if bad_xfo:
            found.append(self.make(
                ctx, title="X-Frame-Options uses an invalid or legacy value",
                severity=LOW, cwe="CWE-1021",
                description=f"Value(s) {', '.join(bad_xfo)} are not DENY or SAMEORIGIN.",
                evidence=f"X-Frame-Options: {', '.join(xfo)}",
                detection_method="Header value validation", confidence=CONFIRMED,
                remediation="Use 'DENY' or 'SAMEORIGIN', or CSP frame-ancestors.",
                tags=["headers"]))
        return found

    async def _transport(self, ctx, resp):
        out = []
        disabled = set(ctx.config.get("modules.disabled", []) or [])
        tls_enabled = "ssl_tls" not in disabled
        if ctx.target.scheme == "http":
            if not tls_enabled:
                return out
            secure = await ctx.http.request("GET", ctx.target.https_url, retry=True)
            if secure.ok and secure.status and secure.status < 400:
                final = resp.final_url or resp.url
                if final.lower().startswith("http://"):
                    out.append(self.make(
                        ctx, title="HTTPS available but no redirect from HTTP",
                        severity=MEDIUM, cwe="CWE-319",
                        description="The plaintext origin serves content directly instead of "
                                    "redirecting to HTTPS, so a first request can be intercepted.",
                        evidence=f"GET {ctx.target.https_url} -> {secure.status} {final}",
                        detection_method="Manual redirect inspection", confidence=CONFIRMED,
                        remediation="Return 301 to the https:// origin for all HTTP requests.",
                        tags=["transport"]))
            else:
                out.append(self.make(
                    ctx, title="HTTPS not available",
                    severity=MEDIUM, cwe="CWE-319",
                    description="The HTTPS origin did not complete a successful request.",
                    evidence=f"GET {ctx.target.https_url} -> {secure.status or secure.error}",
                    detection_method="HTTPS probe", confidence=HIGH_CONF,
                    remediation="Provision a valid certificate and serve over TLS 1.2+.",
                    tags=["transport"]))
        else:
            plain = ctx.target.plain_url
            try:
                p = await ctx.http.request("GET", plain, retry=False)
            except Exception:
                p = None
            loc = p.header("location") if p else ""
            landed_https = bool(
                p and p.ok and p.status < 400
                and ((p.final_url or p.url).startswith("https://")
                     or (p.status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://")))
            )
            redirected = bool(p and (p.hops or p.status in (301, 302, 303, 307, 308)))
            if p and p.ok and p.status < 400 and not landed_https and not redirected:
                out.append(self.make(
                    ctx, title="HTTP origin reachable without redirect to HTTPS",
                    severity=LOW, cwe="CWE-319",
                    description="Content is served over plaintext as well as TLS.",
                    evidence=f"GET {plain} -> {p.status}",
                    detection_method="Plaintext probe", confidence=CONFIRMED,
                    remediation="Force HTTPS with HSTS and a 301 redirect.",
                    tags=["transport"]))
            hsts = resp.header("strict-transport-security")
            if not hsts:
                out.append(self.make(
                    ctx, title="Strict-Transport-Security header absent",
                    severity=MEDIUM, cwe="CWE-319",
                    description="Without HSTS the browser may downgrade to HTTP on the next "
                                "visit, allowing an active attacker to strip TLS.",
                    evidence=f"Response headers:\n{_dump(resp.headers)}",
                    detection_method="Response header inspection", confidence=CONFIRMED,
                    remediation="Send Strict-Transport-Security: max-age=31536000; "
                                "includeSubDomains; preload once HTTPS is stable.",
                    tags=["transport", "hsts"]))
            else:
                m = re.search(r"max-age=(\d+)", hsts)
                if m and int(m.group(1)) < 15552000:
                    out.append(self.make(
                        ctx, title="HSTS max-age below recommended minimum",
                        severity=LOW, cwe="CWE-319",
                        description=f"max-age={m.group(1)} is under 180 days.",
                        evidence=f"Strict-Transport-Security: {hsts}",
                        detection_method="Header value inspection", confidence=CONFIRMED,
                        remediation="Raise max-age to at least 31536000.",
                        tags=["transport", "hsts"]))
        return out

    async def _xcto(self, ctx, resp):
        raw = resp.header("x-content-type-options")
        if raw and "nosniff" not in _header_tokens(resp, "x-content-type-options"):
            return [self.make(
                ctx, title="X-Content-Type-Options set without nosniff",
                severity=LOW, cwe="CWE-693",
                description="The header is present but nosniff is missing from the value.",
                evidence=f"X-Content-Type-Options: {raw}",
                detection_method="Header value validation", confidence=CONFIRMED,
                remediation="Send: X-Content-Type-Options: nosniff", tags=["headers"])]
        return []

    async def _disclosure(self, ctx, resp):
        out = []
        for header in SERVER_HEADERS:
            val = resp.header(header)
            if not val:
                continue
            ver = VERSION_RE.search(val)
            if ver:
                out.append(self.make(
                    ctx, title=f"Software version disclosed via '{header}' header",
                    severity=LOW, cwe="CWE-200",
                    description=f"'{header}: {val}' reveals a specific build, helping an "
                                "attacker map known CVEs.",
                    evidence=f"{header}: {val}",
                    detection_method="Header inspection", confidence=CONFIRMED,
                    remediation="Reduce the header to the product name, or strip it at the edge.",
                    tags=["disclosure", "version"]))
            else:
                out.append(self.make(
                    ctx, title=f"Technology disclosed via '{header}' header",
                    severity=INFO, cwe="CWE-200",
                    description=f"'{header}: {val}' identifies the stack.",
                    evidence=f"{header}: {val}",
                    detection_method="Header inspection", confidence=CONFIRMED,
                    remediation="Optional: normalise or remove identifying headers.",
                    tags=["disclosure"]))
        return out

    async def _methods(self, ctx):
        out = []
        resp = await ctx.http.request("OPTIONS", ctx.target.url, retry=False)
        allow = resp.header("allow") or resp.header("access-control-allow-methods")
        advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = advertised & {"PUT", "DELETE", "TRACE", "PATCH", "DEBUG", "CONNECT"}
        if risky:
            out.append(self.make(
                ctx, title="Uncommon HTTP methods advertised",
                severity=LOW, cwe="CWE-650",
                description=f"OPTIONS reports: {', '.join(sorted(risky))}. Verify each is "
                            "intentional and authenticated where needed.",
                evidence=f"OPTIONS {ctx.target.url} -> {resp.status}\nAllow: {allow}",
                detection_method="OPTIONS probe", confidence=HIGH_CONF,
                remediation="Disable unused verbs at the web server or proxy.",
                tags=["methods"]))
        if "TRACE" in advertised:
            out.append(self.make(
                ctx, title="TRACE method enabled",
                severity=INFO, cwe="CWE-693",
                description="TRACE can echo request headers back, occasionally leaking "
                            "cross-domain cookie behaviour.",
                evidence=f"Allow: {allow}", detection_method="OPTIONS probe",
                confidence=HIGH_CONF,
                remediation="Disable TraceEnable unless needed.", tags=["methods"]))
        return out

    async def _clickjacking(self, ctx, resp):
        xfo = [t for t in _header_tokens(resp, "x-frame-options")
               if t in ("deny", "sameorigin")]
        csp = resp.header("content-security-policy")
        framed = "frame-ancestors" in csp if csp else False
        if xfo or framed:
            return []
        return [self.make(
            ctx, title="Framing not restricted (clickjacking exposure)",
            severity=MEDIUM, cwe="CWE-1021",
            description="Neither X-Frame-Options nor CSP frame-ancestors is present, so the "
                        "site can be embedded in an attacker frame for UI-redress attacks.",
            evidence=f"Response headers:\n{_dump(resp.headers)}",
            detection_method="Header inspection", confidence=CONFIRMED,
            remediation="Send X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
            tags=["clickjacking"])]

    async def _cache_control(self, ctx, resp):
        if resp.status != 200:
            return []
        cc = resp.header("cache-control")
        if not cc:
            return [self.make(
                ctx, title="No Cache-Control directive on HTML response",
                severity=INFO, cwe="CWE-525",
                description="Absent cache directives leave storage behaviour to browser "
                            "heuristics, which can cache authenticated pages.",
                evidence=f"Response headers:\n{_dump(resp.headers)}",
                detection_method="Header inspection", confidence=CONFIRMED,
                remediation="Send explicit Cache-Control (e.g. no-store for private pages).",
                tags=["cache"])]
        return []