"""API surface indicators: docs, versioning, rate-limit headers, error shape."""
from __future__ import annotations

import json
import re

from core.finding import CONFIRMED, HIGH_CONF, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule

DOC_PATHS = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
             "/swagger/", "/docs", "/redoc", "/api/swagger.json", "/v2/api-docs",
             "/graphql", "/api/graphql"]

VERSION_PATHS = ["/v1", "/v2", "/api/v1", "/api/v2"]

RATE_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit",
                "ratelimit-remaining", "retry-after", "x-rate-limit")


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
        return out

    async def _docs(self, ctx):
        out = []
        base = str(ctx.target.root)
        for path in DOC_PATHS:
            url = base.rstrip("/") + path
            resp = await ctx.http.request("GET", url, retry=False)
            if not resp.ok or resp.status >= 400:
                continue
            body = resp.body[:4000]
            looks_doc = ('"openapi"' in body or '"swagger"' in body
                         or "swagger-ui" in body.lower() or '"paths"' in body
                         or ("graphql" in body.lower() and "query" in body.lower()))
            if not looks_doc:
                continue
            sev = HIGH if '"openapi"' in body or '"swagger"' in body else MEDIUM
            out.append(self.make(
                ctx, title=f"Public API specification exposed at {path}",
                severity=sev, cwe="CWE-200",
                description="A machine-readable API description is publicly readable, "
                            "enumerating every endpoint, parameter and schema.",
                evidence=f"GET {url} -> {resp.status}\n{body[:600]}",
                detection_method="Documented-path probe", confidence=CONFIRMED,
                remediation="Confirm the spec is intended to be public; otherwise gate it.",
                tags=["api", "disclosure"]))
            ctx.api_doc_url = url
        return out

    async def _versioning(self, ctx):
        out = []
        base = str(ctx.target.root)
        for path in VERSION_PATHS:
            url = base.rstrip("/") + path
            resp = await ctx.http.request("GET", url, retry=False)
            if resp.ok and resp.status < 400 and len(resp.body) > 20:
                out.append(self.make(
                    ctx, title=f"API version root reachable: {path}",
                    severity=INFO,
                    description="A versioned API root responded. Multiple live versions often "
                                "means older, less-hardened code remains exposed.",
                    evidence=f"GET {url} -> {resp.status}",
                    detection_method="Version-path probe", confidence=HIGH_CONF,
                    remediation="Retire superseded API versions and document deprecation.",
                    tags=["api", "versioning"]))
        return out

    async def _rate_limits(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        present = [h for h in RATE_HEADERS if resp.header(h)]
        if present:
            return [self.make(
                ctx, title="Rate-limit headers present",
                severity=INFO,
                description=f"Advertised headers: {', '.join(present)}",
                evidence="\n".join(f"{h}: {resp.header(h)}" for h in present),
                detection_method="Header inspection", confidence=CONFIRMED,
                remediation="Verify limits actually bind under load.",
                tags=["api", "rate-limit"])]
        return [self.make(
            ctx, title="No rate-limit headers advertised",
            severity=LOW, cwe="CWE-770",
            description="The response exposes no rate-limit signalling. Absence is not proof "
                        "of absent limiting, but no client-visible budget exists.",
            evidence="No X-RateLimit-* / RateLimit-* / Retry-After header",
            detection_method="Header inspection", confidence=NEEDS_MANUAL,
            remediation="Publish standard rate-limit headers and enforce server-side quotas.",
            tags=["api", "rate-limit"])]

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
            ctx, title="404 page leaks internal implementation detail",
            severity=LOW, cwe="CWE-209",
            description=f"Error output exposes: {', '.join(hits)}.",
            evidence=f"GET {url} -> 404\n{body[:700]}",
            detection_method="Error-page inspection", confidence=HIGH_CONF,
            remediation="Serve a generic error page and log detail server-side only.",
            tags=["api", "disclosure", "error"])]