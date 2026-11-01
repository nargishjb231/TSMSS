"""Authentication configuration review: forms, CSRF, JWT, transport."""
from __future__ import annotations

import base64
import json
import re

from bs4 import BeautifulSoup

from core.finding import CONFIRMED, HIGH_CONF, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule

LOGIN_PATHS = ["/login", "/signin", "/admin", "/wp-login.php", "/user/login", "/auth/login"]
CSRF_HINTS = ("csrf", "xsrf", "_token", "authenticity_token", "nonce", "__requestverificationtoken")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


class AuthenticationModule(BaseModule):
    name = "authentication"
    category = "Authentication & Authorization"

    async def run(self, ctx):
        out = []
        found = await self._find_login(ctx)
        if found:
            out += await self._review_form(ctx, found)
        out += self._jwt_scan(ctx)
        out += await self._auth_transport(ctx, found)
        return out

    async def _find_login(self, ctx):
        base = str(ctx.target.root).rstrip("/")
        for path in LOGIN_PATHS:
            url = base + path
            resp = await ctx.http.request("GET", url, retry=False)
            if not resp.ok or resp.status >= 400:
                continue
            soup = BeautifulSoup(resp.body, "html.parser")
            form = soup.find("form")
            if not form:
                continue
            if not form.find("input", {"type": "password"}):
                continue
            ctx.login_url = url
            return (url, resp, soup, form)
        return None

    async def _review_form(self, ctx, found):
        url, resp, soup, form = found
        out = [self.make(
            ctx, title="Authentication form located",
            severity=INFO,
            description=f"A password form is served at {url}.",
            evidence=f"GET {url} -> {resp.status}",
            detection_method="Known-path crawl", confidence=CONFIRMED,
            remediation="Ensure this endpoint is rate limited and monitored.",
            tags=["auth", "inventory"])]

        action = (form.get("action") or "").lower()
        if url.startswith("https://") and action.startswith("http://"):
            out.append(self.make(
                ctx, title="Login form posts to a plaintext action URL",
                severity=HIGH, cwe="CWE-319",
                description="Credentials submitted to an http:// action cross the wire in clear text.",
                evidence=f"form action={form.get('action')}",
                detection_method="Form markup inspection", confidence=CONFIRMED,
                remediation="Post to the https:// origin.", tags=["auth", "transport"]))
        if form.get("method", "get").lower() == "get":
            out.append(self.make(
                ctx, title="Login form uses GET",
                severity=LOW, cwe="CWE-598",
                description="Credentials appear in the URL and may land in logs and Referer headers.",
                evidence="form method=get", detection_method="Form markup inspection",
                confidence=CONFIRMED, remediation="Use method=post.",
                tags=["auth", "transport"]))

        names = {(i.get("name") or "").lower() for i in form.find_all("input")}
        has_csrf = any(any(h in n for h in CSRF_HINTS) for n in names)
        ctx.csrf_token_present = has_csrf
        if not has_csrf:
            out.append(self.make(
                ctx, title="Login form has no anti-CSRF token field",
                severity=MEDIUM, cwe="CWE-352",
                description="No hidden token field was found. Login CSRF lets an attacker log a "
                            "victim into an attacker-controlled account.",
                evidence=f"Input names: {sorted(n for n in names if n)}",
                detection_method="Form markup inspection", confidence=HIGH_CONF,
                remediation="Add a per-session synchroniser token or SameSite=Strict cookies.",
                tags=["auth", "csrf"]))
        if not form.find("input", {"autocomplete": "current-password"}):
            out.append(self.make(
                ctx, title="Password field lacks autocomplete=current-password",
                severity=INFO,
                description="Password managers rely on this hint.",
                evidence="no autocomplete hint on password input",
                detection_method="Form markup inspection", confidence=CONFIRMED,
                remediation="Add autocomplete=current-password and autocomplete=username.",
                tags=["auth", "usability"]))
        ctx.login_fields = sorted(n for n in names if n)
        return out

    def _jwt_scan(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        tokens = set(JWT_RE.findall(resp.body[:200_000]))
        for cookie in resp.get_all("set-cookie"):
            tokens.update(JWT_RE.findall(cookie))
        out = []
        for token in list(tokens)[:3]:
            header = self._decode(token.split(".")[0])
            if not header:
                continue
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                out.append(self.make(
                    ctx, title="JWT uses alg=none",
                    severity=HIGH, cwe="CWE-347",
                    description="Unsecured JWTs carry no signature; any claim can be rewritten.",
                    evidence=f"header={json.dumps(header)}\ntoken={token[:120]}",
                    detection_method="JWT header decode", confidence=CONFIRMED,
                    remediation="Sign tokens and pin the expected algorithm server-side.",
                    tags=["auth", "jwt"]))
            elif alg in ("hs256", "hs384", "hs512"):
                out.append(self.make(
                    ctx, title=f"JWT signed with symmetric algorithm ({alg.upper()})",
                    severity=INFO, cwe="CWE-347",
                    description="Symmetric signing is acceptable; ensure the library is not "
                                "vulnerable to algorithm confusion with RS256 keys.",
                    evidence=f"header={json.dumps(header)}",
                    detection_method="JWT header decode", confidence=HIGH_CONF,
                    remediation="Pin the accepted algorithm explicitly.",
                    tags=["auth", "jwt"]))
            if "kid" in header:
                out.append(self.make(
                    ctx, title="JWT header exposes a 'kid' parameter",
                    severity=INFO, cwe="CWE-347",
                    description="kid is a common path-traversal and injection sink if used "
                                "unsanitised to locate keys.",
                    evidence=f"header={json.dumps(header)}",
                    detection_method="JWT header decode", confidence=NEEDS_MANUAL,
                    remediation="Sanitise kid against a known key set.",
                    tags=["auth", "jwt"]))
        return out

    @staticmethod
    def _decode(segment: str) -> dict | None:
        try:
            pad = segment + "=" * (-len(segment) % 4)
            return json.loads(base64.urlsafe_b64decode(pad))
        except Exception:
            return None

    async def _auth_transport(self, ctx, found):
        out = []
        admin = str(ctx.target.root).rstrip("/") + "/admin"
        resp = await ctx.http.request("GET", admin, retry=False)
        if resp.ok and resp.status == 200 and "password" not in resp.body.lower():
            out.append(self.make(
                ctx, title="Administrative path reachable without immediate auth redirect",
                severity=MEDIUM, cwe="CWE-306",
                description=f"{admin} returned 200 without redirecting to a login page.",
                evidence=f"GET {admin} -> 200, {len(resp.body)} bytes",
                detection_method="Path probe", confidence=HIGH_CONF,
                remediation="Confirm access control is enforced server-side, not by obscurity.",
                tags=["auth", "access-control"]))
        return out