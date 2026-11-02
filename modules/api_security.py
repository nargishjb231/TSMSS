"""OWASP API Security Top 10:2023 (API1-API10) passive & schema indicators."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlsplit

from core.finding import CONFIRMED, HIGH, HIGH_CONF, INFO, LOW, MEDIUM, NEEDS_MANUAL, POTENTIAL
from modules.base import BaseModule
from probe.soft404 import calibrate_soft404, evaluate_path_probe, is_soft404

DOC_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
    "/swagger/", "/docs", "/redoc", "/api/swagger.json", "/v2/api-docs",
    "/graphql", "/api/graphql",
]

VERSION_PATHS = ["/v1", "/v2", "/api/v1", "/api/v2"]

RATE_HEADERS = (
    "x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit",
    "ratelimit-remaining", "retry-after", "x-rate-limit",
)

API_KEY_QUERY_RE = re.compile(r"(?i)^(api[_-]?key|access[_-]?token|auth[_-]?token|jwt|secret|client[_-]?secret)$")
BOPLA_SENSITIVE_KEYS = re.compile(
    r'"(password_hash|hashed_password|salt|secret_key|private_key|ssn|tax_id|credit_card|cvv|internal_notes)"\s*:',
    re.I,
)
PAGINATION_PARAMS = re.compile(r"(?i)^(limit|page_?size|per_?page|max_?results|count|batch_?size)$")
BFLA_ADMIN_ROUTES = re.compile(r"(?i)(/api/(?:v\d+/)?(?:admin|internal|debug|management|superuser|staff|actuator)[/\w\-]*)")
BUSINESS_FLOW_ROUTES = re.compile(r"(?i)/(checkout|redeem|coupon|voucher|transfer|withdraw|referral|airdrop|claim)\b")
WEBHOOK_URL_PARAMS = re.compile(r"(?i)^(webhook|webhook_?url|callback_?url|notify_?url|ping_?url|import_?url|fetch_?url)$")
THIRD_PARTY_TRUST_RE = re.compile(r"(?i)(x-forwarded-host|x-original-url|x-rewrite-url|webhook-signature)")


class ApiSecurityModule(BaseModule):
    name = "api_security"
    category = "API Security"

    async def run(self, ctx):
        out = []
        if not ctx.config.get("active.param_discovery", True):
            return out
        out += await self._docs(ctx)
        out += await self._versioning(ctx)
        out += await self._rate_limits(ctx)
        out += await self._error_shape(ctx)
        out += self._owasp_api_top10_passive(ctx)
        return out

    async def _docs(self, ctx):
        out = []
        if getattr(ctx, "edge_challenged", False):
            return out
        base = str(ctx.target.root)
        baseline = await calibrate_soft404(ctx)
        no_soft404 = bool(ctx.config.get("scan.no_soft404", False))
        for path in DOC_PATHS:
            url = base.rstrip("/") + path
            resp = await ctx.http.request("GET", url, retry=False)
            if not resp.ok or resp.status >= 400:
                continue
            if getattr(resp, "edge_challenged", False):
                continue
            body = resp.body[:12000]
            default_sev = HIGH if ('"openapi"' in body or '"swagger"' in body) else MEDIUM
            reportable, eff_sev, reason = evaluate_path_probe(
                path, resp.status, body, default_sev, baseline, no_soft404=no_soft404
            )
            if not reportable:
                continue
            if reason.startswith("soft-404"):
                if path == "/swagger-ui.html" and baseline.is_spa:
                    out.append(self.make(
                        ctx,
                        title=f"Soft-404 response on API doc path ({path})",
                        severity=INFO,
                        cwe="CWE-200",
                        description=f"{path} returned HTTP 200 with the SPA catch-all shell rather than API documentation.",
                        evidence=f"GET {url} -> 200 [{reason}: soft-404]",
                        detection_method="Soft-404 calibrated path probe",
                        confidence=CONFIRMED,
                        url=url,
                        remediation="Informational: SPA catch-all route.",
                        tags=["api", "soft-404"],
                    ))
                continue
            if not no_soft404 and is_soft404(resp.status, resp.body, baseline):
                continue
            if hasattr(ctx, "seen_paths"):
                ctx.seen_paths.add(path)
            out.append(self.make(
                ctx,
                title=f"API specification or console exposed at {path}",
                severity=eff_sev,
                cwe="CWE-200",
                description="Public API documentation enumerates endpoints, parameters and auth schemes (API9:2023).",
                evidence=f"GET {url} -> {resp.status}\n{body[:500]}",
                detection_method="Known-path probe",
                confidence=CONFIRMED,
                url=url,
                remediation="Restrict API documentation to authenticated internal networks.",
                tags=["api", "API9:2023", "openapi"],
            ))
            out += self._analyze_openapi_spec(ctx, url, resp.body)
        return out

    def _analyze_openapi_spec(self, ctx, spec_url: str, raw_body: str):
        out = []
        if not raw_body.lstrip().startswith("{"):
            return out
        try:
            spec = json.loads(raw_body[:300_000])
        except Exception:
            return out
        if not isinstance(spec, dict):
            return out
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            return out

        object_id_routes = [p for p in paths if re.search(r"\{[A-Za-z0-9_]*id\}", str(p), re.I)]
        admin_routes = [p for p in paths if re.search(r"(?i)/(admin|internal|debug|staff|management)\b", str(p))]

        if object_id_routes:
            out.append(self.make(
                ctx,
                title="API1:2023 BOLA — Object-ID parameterized API routes in specification",
                severity=INFO,
                cwe="CWE-639",
                description=f"OpenAPI specification defines {len(object_id_routes)} route(s) accepting object identifiers. Verify per-object ownership checks with two test accounts.",
                evidence=f"Spec: {spec_url}\nRoutes: {', '.join(object_id_routes[:8])}",
                detection_method="OpenAPI schema analysis",
                confidence=NEEDS_MANUAL,
                url=spec_url,
                remediation="Enforce server-side object-level authorization checks on every record access.",
                tags=["api", "API1:2023", "bola"],
            ))
        if admin_routes:
            out.append(self.make(
                ctx,
                title="API5:2023 BFLA — Administrative API routes listed in public specification",
                severity=LOW,
                cwe="CWE-285",
                description=f"Public API specification exposes {len(admin_routes)} administrative/internal endpoint(s).",
                evidence=f"Spec: {spec_url}\nAdmin routes: {', '.join(admin_routes[:8])}",
                detection_method="OpenAPI schema analysis",
                confidence=POTENTIAL,
                url=spec_url,
                remediation="Segregate administrative APIs and enforce strict role-based function-level authorization.",
                tags=["api", "API5:2023", "bfla"],
            ))
        return out

    async def _versioning(self, ctx):
        live = []
        base = str(ctx.target.root).rstrip("/")
        for v in VERSION_PATHS:
            url = base + v
            resp = await ctx.http.request("GET", url, retry=False)
            if resp.ok and resp.status in (200, 401, 403) and "application/json" in resp.header("content-type"):
                live.append(f"{v} ({resp.status})")
        if len(live) >= 2:
            return [self.make(
                ctx,
                title="API9:2023 — Multiple API versions concurrently reachable",
                severity=LOW,
                cwe="CWE-1059",
                description="Older API versions often lack controls added to newer ones (shadow/deprecated API risk).",
                evidence=", ".join(live),
                detection_method="Version-prefix probe",
                confidence=CONFIRMED,
                remediation="Retire deprecated API versions or apply identical security controls across all versions.",
                tags=["api", "API9:2023", "versioning"],
            )]
        return []

    async def _rate_limits(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        present = {h: resp.header(h) for h in RATE_HEADERS if resp.header(h)}
        if present:
            return [self.make(
                ctx,
                title="Rate-limit headers advertised",
                severity=INFO,
                description="Rate-limit headers were observed on the response.",
                evidence="\n".join(f"{k}: {v}" for k, v in present.items()),
                detection_method="Header inspection",
                confidence=CONFIRMED,
                remediation="Informational.",
                tags=["api", "API4:2023", "rate-limit"],
            )]
        return [self.make(
            ctx,
            title="No rate-limit headers advertised",
            severity=LOW,
            cwe="CWE-770",
            description="The response exposes no rate-limit signalling (API4:2023). Absence is not proof "
                        "of absent limiting, but no client-visible budget exists.",
            evidence="No X-RateLimit-* / RateLimit-* / Retry-After header",
            detection_method="Header inspection",
            confidence=NEEDS_MANUAL,
            remediation="Publish standard rate-limit headers and enforce server-side quotas.",
            tags=["api", "API4:2023", "rate-limit"],
        )]

    async def _error_shape(self, ctx):
        url = str(ctx.target.root).rstrip("/") + "/tsmss-nonexistent-8f3a2c"
        resp = await ctx.http.request("GET", url, retry=False)
        if not resp.ok or resp.status != 404:
            return []
        body = resp.body
        markers = {
            "stack trace": r"(Traceback \(most recent call last\)|at [\w.$]+\([\w.]+:\d+\))",
            "framework path": r"(/var/www|C:\\\\|/home/\w+|/usr/local/lib)",
            "SQL text": r"(SQLSTATE|ORA-\d{5}|MySQLSyntaxErrorException|pg_query)",
            "debug flag": r"(debug\s*[=:]\s*true|APP_DEBUG|DJANGO_SETTINGS_MODULE)",
        }
        hits = [label for label, pat in markers.items() if re.search(pat, body, re.I)]
        if not hits:
            return []
        return [self.make(
            ctx,
            title="404 page leaks internal implementation detail",
            severity=LOW,
            cwe="CWE-209",
            description=f"Error output exposes: {', '.join(hits)} (API8:2023).",
            evidence=f"GET {url} -> 404\n{body[:700]}",
            detection_method="Error-page inspection",
            confidence=HIGH_CONF,
            remediation="Serve a generic error page and log detail server-side only.",
            tags=["api", "API8:2023", "disclosure", "error"],
        )]

    def _owasp_api_top10_passive(self, ctx):
        """Passive checks for API2, API3, API4, API5, API6, API7, API10 on the fetched response."""
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        out = []
        body = resp.body or ""
        query_params = parse_qs(urlsplit(ctx.target.url).query, keep_blank_values=True)

        # API2:2023 Broken Authentication — API key/token in URL query string
        auth_query_keys = [k for k in query_params if API_KEY_QUERY_RE.match(k)]
        if auth_query_keys:
            out.append(self.make(
                ctx,
                title=f"API2:2023 — Credential or token parameter '{auth_query_keys[0]}' passed in URL query",
                severity=MEDIUM,
                cwe="CWE-598",
                description="Passing API keys or bearer tokens in URL query parameters exposes them in browser history, Referer headers, and proxy logs.",
                evidence=f"Query parameter(s): {', '.join(auth_query_keys)}",
                detection_method="URL parameter inspection",
                confidence=CONFIRMED,
                parameter=auth_query_keys[0],
                remediation="Transmit API tokens exclusively via the HTTP Authorization header.",
                tags=["api", "API2:2023", "auth"],
            ))

        # API3:2023 BOPLA — Sensitive internal properties in JSON response
        bopla_hits = sorted({m.group(1) for m in BOPLA_SENSITIVE_KEYS.finditer(body)})
        if bopla_hits:
            out.append(self.make(
                ctx,
                title="API3:2023 BOPLA — Sensitive object properties exposed in response payload",
                severity=HIGH,
                cwe="CWE-213",
                description=f"Response payload contains sensitive property keys ({', '.join(bopla_hits[:6])}) that should not be serialized to clients.",
                evidence="Matched keys: " + ", ".join(bopla_hits[:6]),
                detection_method="Passive JSON property inspection",
                confidence=HIGH_CONF,
                remediation="Use explicit DTO/response schemas (e.g. Pydantic/Marshmallow) and strip internal fields before serialization.",
                tags=["api", "API3:2023", "bopla"],
            ))

        # API4:2023 Unrestricted Resource Consumption — Pagination/batch size parameters
        page_keys = [k for k in query_params if PAGINATION_PARAMS.match(k)]
        if page_keys:
            out.append(self.make(
                ctx,
                title=f"API4:2023 — Pagination/batch parameter '{page_keys[0]}' requires server-side cap review",
                severity=INFO,
                cwe="CWE-770",
                description="Endpoint accepts a client-controlled batch/page size parameter; verify the server enforces a strict maximum limit.",
                evidence=f"Parameter(s): {', '.join(page_keys)}",
                detection_method="Passive parameter classification",
                confidence=NEEDS_MANUAL,
                parameter=page_keys[0],
                remediation="Enforce a strict upper bound (e.g. max 100 items per page) and reject negative or huge limit values.",
                tags=["api", "API4:2023", "resource-consumption"],
            ))

        # API5:2023 BFLA — Administrative API routes referenced in client markup
        bfla_hits = sorted({m.group(1) for m in BFLA_ADMIN_ROUTES.finditer(body)})
        if bfla_hits:
            out.append(self.make(
                ctx,
                title="API5:2023 BFLA — Administrative API route references in client response",
                severity=LOW,
                cwe="CWE-285",
                description="Client response references administrative or internal API paths; verify role-based access control on each route.",
                evidence="Referenced routes: " + ", ".join(bfla_hits[:6]),
                detection_method="Passive route pattern scan",
                confidence=NEEDS_MANUAL,
                remediation="Verify server-side function-level authorization denies non-administrative roles on these routes.",
                tags=["api", "API5:2023", "bfla"],
            ))

        # API6:2023 Sensitive Business Flow Abuse — High-value business flow path without anti-automation indicator
        if BUSINESS_FLOW_ROUTES.search(urlsplit(ctx.target.url).path or ""):
            has_bot_guard = bool(re.search(r"(?i)(captcha|recaptcha|turnstile|hcaptcha|cf-chl)", body))
            if not has_bot_guard:
                out.append(self.make(
                    ctx,
                    title="API6:2023 — Sensitive business workflow endpoint without visible anti-automation guard",
                    severity=INFO,
                    cwe="CWE-799",
                    description="Target path matches a sensitive business flow (checkout/redeem/coupon/transfer) without visible CAPTCHA or anti-automation markers.",
                    evidence=f"URL: {ctx.target.url}",
                    detection_method="Passive workflow indicator check",
                    confidence=NEEDS_MANUAL,
                    remediation="Enforce per-account rate limits, idempotency keys, and anti-automation controls on sensitive business flows.",
                    tags=["api", "API6:2023", "business-flow"],
                ))

        # API7:2023 & API10:2023 — Webhook / third-party callback URL parameters
        webhook_keys = [k for k in query_params if WEBHOOK_URL_PARAMS.match(k)]
        if webhook_keys:
            out.append(self.make(
                ctx,
                title=f"API7:2023 / API10:2023 — Outbound webhook/callback parameter '{webhook_keys[0]}' detected",
                severity=LOW,
                cwe="CWE-918",
                description="Parameter name indicates outbound URL fetching or third-party webhook registration (SSRF & unsafe API consumption surface).",
                evidence=f"Parameter: {webhook_keys[0]}",
                detection_method="Passive parameter classification",
                confidence=NEEDS_MANUAL,
                parameter=webhook_keys[0],
                remediation="Validate outbound URLs against an explicit domain allowlist, block RFC1918/metadata IPs, and verify webhook signatures.",
                tags=["api", "API7:2023", "API10:2023", "ssrf"],
            ))

        return out
