"""Cookie attribute review."""
from __future__ import annotations

import time

from core.finding import CONFIRMED, HIGH, INFO, LOW, MEDIUM
from modules.base import BaseModule

SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "remember", "csrf", "xsrf")


class CookieModule(BaseModule):
    name = "cookies"
    category = "Cookie & Session Security"

    async def run(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            resp = await ctx.http.request("GET", ctx.target.url)
        out = []
        for raw in resp.set_cookies:
            out += self._review(ctx, raw, resp)
        return out

    def _review(self, ctx, raw: str, resp):
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            return []
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower(): p for p in parts[1:]}
        secure = ctx.target.scheme == "https"
        sessionish = any(h in name.lower() for h in SESSION_HINTS)
        out = []

        if "secure" not in attrs and secure:
            out.append(self.make(
                ctx, title=f"Cookie '{name}' lacks the Secure flag",
                severity=HIGH if sessionish else LOW, cwe="CWE-614",
                description="The cookie can be sent over plaintext HTTP, exposing it to "
                            "network interception.",
                evidence=f"Set-Cookie: {raw}", detection_method="Set-Cookie inspection",
                confidence=CONFIRMED,
                remediation=f"Set-Cookie: {name}=...; Secure", tags=["cookie", "transport"]))
        if "httponly" not in attrs:
            out.append(self.make(
                ctx, title=f"Cookie '{name}' lacks HttpOnly",
                severity=MEDIUM if sessionish else LOW, cwe="CWE-1004",
                description="JavaScript can read the cookie, so any XSS escalates to session "
                            "theft.",
                evidence=f"Set-Cookie: {raw}", detection_method="Set-Cookie inspection",
                confidence=CONFIRMED,
                remediation=f"Set-Cookie: {name}=...; HttpOnly", tags=["cookie", "xss"]))
        samesite = attrs.get("samesite", "").lower()
        if "samesite" not in attrs:
            out.append(self.make(
                ctx, title=f"Cookie '{name}' has no SameSite attribute",
                severity=MEDIUM if sessionish else LOW, cwe="CWE-1275",
                description="Browsers default inconsistently; the cookie may ride along on "
                            "cross-site requests, enabling CSRF.",
                evidence=f"Set-Cookie: {raw}", detection_method="Set-Cookie inspection",
                confidence=CONFIRMED,
                remediation=f"Set-Cookie: {name}=...; SameSite=Lax (or Strict)",
                tags=["cookie", "csrf"]))
        elif "samesite=none" in samesite and "secure" not in attrs:
            out.append(self.make(
                ctx, title=f"Cookie '{name}' uses SameSite=None without Secure",
                severity=MEDIUM, cwe="CWE-1275",
                description="SameSite=None requires Secure; without it the cookie is dropped "
                            "in cross-site contexts.",
                evidence=f"Set-Cookie: {raw}", detection_method="Set-Cookie inspection",
                confidence=CONFIRMED, remediation="Add the Secure attribute.",
                tags=["cookie"]))
        if "expires" in attrs or "max-age" in attrs:
            max_age = attrs.get("max-age", "")
            try:
                lifetime = int(max_age.split("=", 1)[1]) if max_age else None
            except (ValueError, IndexError):
                lifetime = None
            if lifetime and lifetime > 60 * 60 * 24 * 365:
                out.append(self.make(
                    ctx, title=f"Cookie '{name}' lifetime exceeds one year",
                    severity=INFO, cwe="CWE-539",
                    description="Long-lived cookies widen the window for replay after theft.",
                    evidence=f"Set-Cookie: {raw}", detection_method="Set-Cookie inspection",
                    confidence=CONFIRMED, remediation="Shorten lifetime or rotate tokens.",
                    tags=["cookie"]))
        else:
            out.append(self.make(
                ctx, title=f"Cookie '{name}' is a session cookie (no expiry)",
                severity=INFO,
                description="Expires when the browser closes.",
                evidence=f"Set-Cookie: {raw}", detection_method="Set-Cookie inspection",
                confidence=CONFIRMED, remediation="Appropriate for sessions; ensure idle timeout.",
                tags=["cookie", "inventory"]))
        if len(parts[0].split("=", 1)[1]) > 4096:
            out.append(self.make(
                ctx, title=f"Cookie '{name}' value is unusually large",
                severity=INFO, description="Values over 4 KB risk per-cookie limits.",
                evidence=f"length={len(parts[0])}", detection_method="Set-Cookie inspection",
                confidence=CONFIRMED, remediation="Store bulky data server-side.",
                tags=["cookie"]))
        if name.startswith("__Host-") and ("domain" in attrs or "path=/" not in raw.lower()):
            out.append(self.make(
                ctx, title=f"Cookie '{name}' misuses the __Host- prefix",
                severity=LOW, cwe="CWE-614",
                description="__Host- cookies must be Secure, Path=/, and have no Domain.",
                evidence=f"Set-Cookie: {raw}", detection_method="Set-Cookie inspection",
                confidence=CONFIRMED, remediation="Drop Domain and set Path=/.",
                tags=["cookie"]))
        return out