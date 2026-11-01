"""Authorization design review: control model, IDOR surface, privilege hints."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

from core.finding import CONFIRMED, HIGH_CONF, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule

ID_PARAM = re.compile(r"(?i)^(id|uid|user_?id|account|order|invoice|doc|file|pid|item|customer)$")
ROLE_WORDS = ("admin", "role", "is_admin", "privilege", "scope", "permission", "group")


class AuthorizationModule(BaseModule):
    name = "authorization"
    category = "Authentication & Authorization"

    async def run(self, ctx):
        out = []
        out += await self._idor_surface(ctx)
        out += self._role_exposure(ctx)
        out += await self._method_override(ctx)
        return out

    async def _idor_surface(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        url = ctx.target.url
        params = parse_qs(urlparse(url).query)
        numeric = [(k, v[0]) for k, v in params.items() if ID_PARAM.match(k) and v[0].isdigit()]
        if not numeric:
            return []
        out = []
        for key, value in numeric[:3]:
            mutated = dict(params)
            mutated[key] = [str(int(value) + 1)]
            new_url = urlunparse(urlparse(url)._replace(query=urlencode(mutated, doseq=True)))
            probe = await ctx.http.request("GET", new_url, retry=False)
            if not probe.ok or probe.status != resp.status:
                continue
            same = _similarity(resp.body, probe.body)
            if same > 0.985:
                out.append(self.make(
                    ctx, title=f"Possible IDOR: parameter '{key}' returned near-identical content",
                    severity=MEDIUM, cwe="CWE-639",
                    description=f"Incrementing {key} from {value} to {int(value)+1} produced a "
                                f"response {same*100:.1f}% similar. If both records are readable "
                                "by the same unauthenticated client, object-level authorization "
                                "may be missing.",
                    evidence=f"{url}\nvs\n{new_url}\nsimilarity={same:.4f}",
                    detection_method="Parameter increment diff", confidence=NEEDS_MANUAL,
                    remediation="Verify server-side ownership checks per object.",
                    parameter=key, tags=["authorization", "idor"]))
            else:
                out.append(self.make(
                    ctx, title=f"Object reference parameter '{key}' is enumerable",
                    severity=INFO, cwe="CWE-639",
                    description="Changing the identifier returns a distinct record; sequential "
                                "identifiers ease enumeration.",
                    evidence=f"{url}\nvs\n{new_url}\nsimilarity={same:.4f}",
                    detection_method="Parameter increment diff", confidence=HIGH_CONF,
                    remediation="Confirm ownership checks; consider opaque identifiers.",
                    parameter=key, tags=["authorization", "idor"]))
        return out

    def _role_exposure(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        hits = [w for w in ROLE_WORDS if re.search(rf'"{w}"\s*:', resp.body, re.I)]
        if not hits:
            return []
        return [self.make(
            ctx, title="Client-visible role or permission fields",
            severity=INFO, cwe="CWE-639",
            description=f"Response JSON contains role-related keys: {', '.join(hits[:6])}. "
                        "Client-trusted role flags are a frequent privilege-escalation vector.",
            evidence="keys: " + ", ".join(hits[:6]),
            detection_method="Response key scan", confidence=NEEDS_MANUAL,
            remediation="Recompute authorization server-side; never trust client role claims.",
            tags=["authorization", "rbac"])]

    async def _method_override(self, ctx):
        url = ctx.target.url
        resp = await ctx.http.request("POST", url, retry=False,
                                      headers={"X-HTTP-Method-Override": "PUT"},
                                      data={"tsmss": "1"})
        if resp.ok and resp.status < 400 and resp.header("allow"):
            return [self.make(
                ctx, title="Server honours X-HTTP-Method-Override",
                severity=INFO, cwe="CWE-650",
                description="Method override is enabled; confirm per-route authorization is "
                            "evaluated against the effective method, not the transport method.",
                evidence=f"POST with override -> {resp.status}",
                detection_method="Override header probe", confidence=HIGH_CONF,
                remediation="Authorize on the resolved method.", tags=["authorization"])]
        return []


def _similarity(a: str, b: str) -> float:
    import difflib
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()