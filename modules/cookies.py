"""Cookie attribute review (Work Item G)."""
from __future__ import annotations

import re

from core.finding import CONFIRMED, INFO, LOW, MEDIUM
from modules.base import BaseModule

HTTPONLY_EXEMPT: set[str] = {"xsrf-token", "csrf_token", "x-csrf-token", "_csrf"}

SESSION_LIKE_RE = re.compile(
    r"(?i)(session|sess_id|auth|token|jwt|sid|connect\.sid|phpsessid|jsessionid)"
)


def is_httponly_exempt(name: str) -> bool:
    """Return True if *name* is an intentionally JS-readable CSRF cookie (G1)."""
    return name.strip().lower() in HTTPONLY_EXEMPT


def is_session_like(name: str) -> bool:
    """Return True if *name* matches the session-like cookie pattern (G2)."""
    low = name.strip().lower()
    if low in HTTPONLY_EXEMPT:
        return False
    return bool(SESSION_LIKE_RE.search(low))


class CookieModule(BaseModule):
    name = "cookies"
    category = "Cookie & Session Security"

    async def run(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            resp = await ctx.http.request("GET", ctx.target.url)
        out = []
        for raw in resp.get_all("set-cookie"):
            out += self._review(ctx, raw, resp)
        return out

    def audit_lines(self, ctx, lines: list[str]) -> list:
        """Audit a list of raw `Set-Cookie` header lines directly."""
        out = []
        for line in lines:
            s = line.strip()
            if not s:
                continue
            if s.lower().startswith("set-cookie:"):
                s = s.split(":", 1)[1].strip()
            out += self._review(ctx, s, None)
        return out

    def _review(self, ctx, raw: str, resp=None):
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            return []
        name, val = parts[0].split("=", 1)
        name = name.strip()
        name_low = name.lower()

        attrs: dict[str, str] = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[p.strip().lower()] = ""

        exempt_csrf = is_httponly_exempt(name)
        sessionish = is_session_like(name)
        out = []

        # G3: __Host- and __Secure- prefix validation
        if name.startswith("__Host-"):
            path_val = attrs.get("path", "")
            if "secure" not in attrs or "domain" in attrs or path_val != "/":
                out.append(self.make(
                    ctx,
                    title=f"Cookie '{name}' violates __Host- prefix requirements",
                    severity=MEDIUM,
                    cwe="CWE-614",
                    description="__Host- cookies must set Secure, Path=/, and omit the Domain attribute.",
                    evidence=f"Set-Cookie: {raw}",
                    detection_method="Set-Cookie prefix inspection",
                    confidence=CONFIRMED,
                    remediation=f"Set-Cookie: {name}=...; Secure; Path=/; SameSite=Lax",
                    tags=["cookie", "prefix"],
                ))
        elif name.startswith("__Secure-"):
            if "secure" not in attrs:
                out.append(self.make(
                    ctx,
                    title=f"Cookie '{name}' violates __Secure- prefix requirements",
                    severity=MEDIUM,
                    cwe="CWE-614",
                    description="__Secure- cookies must include the Secure attribute.",
                    evidence=f"Set-Cookie: {raw}",
                    detection_method="Set-Cookie prefix inspection",
                    confidence=CONFIRMED,
                    remediation=f"Set-Cookie: {name}=...; Secure",
                    tags=["cookie", "prefix"],
                ))

        # G2: Missing Secure
        if "secure" not in attrs:
            out.append(self.make(
                ctx,
                title=f"Cookie '{name}' lacks the Secure flag",
                severity=MEDIUM if (sessionish or exempt_csrf) else LOW,
                cwe="CWE-614",
                description="The cookie can be transmitted over plaintext HTTP, exposing it to interception.",
                evidence=f"Set-Cookie: {raw}",
                detection_method="Set-Cookie inspection",
                confidence=CONFIRMED,
                remediation=f"Set-Cookie: {name}=...; Secure",
                tags=["cookie", "transport"],
            ))

        # G1 & G2: Missing HttpOnly (exempt for HTTPONLY_EXEMPT CSRF cookies)
        if "httponly" not in attrs and not exempt_csrf:
            out.append(self.make(
                ctx,
                title=f"Cookie '{name}' lacks HttpOnly",
                severity=MEDIUM if sessionish else LOW,
                cwe="CWE-1004",
                description="JavaScript can read the cookie, allowing XSS to steal session identifiers.",
                evidence=f"Set-Cookie: {raw}",
                detection_method="Set-Cookie inspection",
                confidence=CONFIRMED,
                remediation=f"Set-Cookie: {name}=...; HttpOnly",
                tags=["cookie", "xss"],
            ))

        # G2: Missing SameSite (LOW for session-like and general cookies)
        samesite_val = attrs.get("samesite", "").lower()
        if "samesite" not in attrs:
            out.append(self.make(
                ctx,
                title=f"Cookie '{name}' has no SameSite attribute",
                severity=LOW,
                cwe="CWE-1275",
                description="Without an explicit SameSite attribute, cross-site request behaviour depends on browser defaults.",
                evidence=f"Set-Cookie: {raw}",
                detection_method="Set-Cookie inspection",
                confidence=CONFIRMED,
                remediation=f"Set-Cookie: {name}=...; SameSite=Lax (or Strict)",
                tags=["cookie", "csrf"],
            ))
        elif samesite_val == "none" and "secure" not in attrs:
            out.append(self.make(
                ctx,
                title=f"Cookie '{name}' uses SameSite=None without Secure",
                severity=MEDIUM,
                cwe="CWE-1275",
                description="SameSite=None requires Secure; browsers reject SameSite=None cookies without Secure.",
                evidence=f"Set-Cookie: {raw}",
                detection_method="Set-Cookie inspection",
                confidence=CONFIRMED,
                remediation="Add the Secure attribute.",
                tags=["cookie"],
            ))

        # Excessive cookie size (>4KB)
        if len(val) > 4096:
            out.append(self.make(
                ctx,
                title=f"Cookie '{name}' value is unusually large",
                severity=INFO,
                description="Values over 4 KB risk browser per-cookie truncation or rejection.",
                evidence=f"length={len(parts[0])}",
                detection_method="Set-Cookie inspection",
                confidence=CONFIRMED,
                remediation="Store bulky state server-side.",
                tags=["cookie"],
            ))

        return out
