"""Live tests against a local deliberately-insecure fixture server."""
from __future__ import annotations

import asyncio
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import Config
from core.context import ScanContext, Target
from core.rate_limiter import RateLimiter
from core.scope import ScopeGuard
from modules import (authentication, cookies, cors, headers, http_security,
                     information_disclosure, vulnerability_indicators)

PAGE = b"""<html><head><title>fixture</title></head><body>
<h1>hi</h1><a href="/echo?q=1&amp;amp;display=grid">x</a>
<form action="/echo" method="get"><input name="q"></form></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body: bytes, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        import html as htmllib
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/echo":
            q = qs.get("q", [""])[0]
            if q.endswith("'"):
                return self._send(500, b"<html>SQL syntax error near '''</html>")
            return self._send(200, f"<html><body>echo: {q}</body></html>".encode())
        if parsed.path == "/safe-echo":
            q = htmllib.escape(qs.get("q", [""])[0], quote=True)
            return self._send(200, f'<html><body><input name="q" value="{q}"></body></html>'.encode())
        if parsed.path == "/login":
            # Empty SPA form with unnamed password input
            return self._send(200, b'<html><body><form><input type="email"><input type="password"></form></body></html>')
        if parsed.path == "/.env":
            return self._send(200, b"APP_KEY=base64:abc\nDB_PASSWORD=secret\n")
        if parsed.path == "/open":
            target = qs.get("url", ["/"])[0]
            return self._send(302, b"", {"Location": target})
        return self._send(200, PAGE, {"Set-Cookie": "sid=abc; Path=/"})


class Fixture:
    def __enter__(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.port}/"

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


def make_ctx(url, config):
    scope = ScopeGuard([], allow_private=True)
    limiter = RateLimiter(20, 20)

    class FakeHttp:
        def __init__(self):
            import httpx
            self.c = httpx.AsyncClient(follow_redirects=False)
            self.scope = scope

        async def request(self, method, u, retry=True, allow_redirects=False, **kw):
            from core.http_client import Fetched, Hop, _extract_multi_headers
            try:
                r = await self.c.request(method, u, **kw)
            except Exception as exc:
                return Fetched(u, 0, {}, "", 0.0, error=str(exc))
            hops = []
            if allow_redirects:
                cur, status, hdrs = u, r.status_code, dict(r.headers)
                for _ in range(5):
                    loc = hdrs.get("location")
                    if not loc or status not in (301, 302, 303, 307, 308):
                        break
                    nxt = str(r.url.join(loc))
                    hops.append(Hop(cur, status, nxt))
                    cur = nxt
                    try:
                        rr = await self.c.request("GET", nxt)
                    except Exception:
                        # mirror HttpClient._walk_redirects: keep the hop, stop walking
                        break
                    status, hdrs = rr.status_code, dict(rr.headers)
                    r = rr
            return Fetched(u, r.status_code, {k.lower(): v for k, v in r.headers.items()},
                           r.text, 1.0, hops=hops, final_url=str(r.url),
                           set_cookies=r.headers.get_list("set-cookie"),
                           multi_headers=_extract_multi_headers(r.headers))

        async def aclose(self):
            await self.c.aclose()

    return ScanContext(target=Target(url), config=config, scope=scope,
                       http=FakeHttp(), stop_event=asyncio.Event(), counter={"requests": 0})


class TestFixture(unittest.IsolatedAsyncioTestCase):
    def cfg(self):
        c = Config()
        c.set("active.max_params_per_target", 5)
        return c

    async def test_missing_headers_detected(self):
        with Fixture() as url:
            ctx = make_ctx(url, self.cfg())
            out = await http_security.HttpSecurityModule({}).run(ctx)
            titles = " ".join(f.title for f in out)
            self.assertIn("Content-Security-Policy", titles)
            self.assertIn("clickjacking", titles.lower())
            await ctx.http.aclose()

    async def test_cookie_flags(self):
        with Fixture() as url:
            ctx = make_ctx(url, self.cfg())
            out = await cookies.CookieModule().run(ctx)
            titles = " ".join(f.title for f in out)
            self.assertIn("HttpOnly", titles)
            self.assertIn("SameSite", titles)
            await ctx.http.aclose()

    async def test_env_exposure(self):
        with Fixture() as url:
            ctx = make_ctx(url, self.cfg())
            out = await information_disclosure.InformationDisclosureModule().run(ctx)
            self.assertTrue(any(".env" in f.title for f in out))
            await ctx.http.aclose()

    async def test_reflected_xss(self):
        with Fixture() as url:
            ctx = make_ctx(url + "echo?q=1", self.cfg())
            out = await vulnerability_indicators.VulnerabilityIndicatorModule().run(ctx)
            self.assertTrue(any("XSS" in f.title for f in out))
            await ctx.http.aclose()

    async def test_sql_error(self):
        with Fixture() as url:
            ctx = make_ctx(url + "echo?q=1", self.cfg())
            out = await vulnerability_indicators.VulnerabilityIndicatorModule().run(ctx)
            self.assertTrue(any("SQL" in f.title for f in out))
            await ctx.http.aclose()

    async def test_cors_wildcard(self):
        with Fixture() as url:
            ctx = make_ctx(url, self.cfg())
            out = await cors.CorsModule().run(ctx)
            self.assertTrue(any("CORS" in f.title for f in out))
            await ctx.http.aclose()

    async def test_open_redirect(self):
        with Fixture() as url:
            ctx = make_ctx(url + "open?url=/", self.cfg())
            out = await vulnerability_indicators.VulnerabilityIndicatorModule().run(ctx)
            self.assertTrue(any("redirect" in f.title.lower() for f in out))
            await ctx.http.aclose()

    async def test_https_probe_gated_on_ssl_tls_module(self):
        with Fixture() as url:
            cfg = self.cfg()
            cfg.set("modules.disabled", ["ssl_tls"])
            ctx = make_ctx(url, cfg)
            requested_urls = []
            orig_request = ctx.http.request

            async def tracking_request(method, u, **kw):
                requested_urls.append(u)
                return await orig_request(method, u, **kw)

            ctx.http.request = tracking_request
            out = await http_security.HttpSecurityModule({}).run(ctx)
            self.assertFalse(any(u.startswith("https://") for u in requested_urls),
                             f"unexpected https probe when ssl_tls disabled: {requested_urls}")
            self.assertFalse(any("HTTPS" in f.title for f in out))
            await ctx.http.aclose()

    async def test_false_positive_guards(self):
        with Fixture() as url:
            # 1. Encoded XSS reflection is INFO, never HIGH/MEDIUM
            ctx_xss = make_ctx(url + "safe-echo?q=hello", self.cfg())
            out_xss = await vulnerability_indicators.VulnerabilityIndicatorModule().run(ctx_xss)
            xss_findings = [f for f in out_xss if "XSS" in f.title or "reflects" in f.title]
            self.assertEqual(len(xss_findings), 1, xss_findings)
            self.assertEqual(xss_findings[0].severity, "INFO")
            await ctx_xss.http.aclose()

            # 2. Empty SPA login form with unnamed inputs is not flagged as missing CSRF or GET login
            ctx_auth = make_ctx(url, self.cfg())
            out_auth = await authentication.AuthenticationModule().run(ctx_auth)
            self.assertFalse(any("CSRF" in f.title for f in out_auth), out_auth)
            self.assertFalse(any("uses GET" in f.title for f in out_auth), out_auth)
            await ctx_auth.http.aclose()

            # 3. amp;display parameter is cleaned to display, never amp;display
            ctx_home = make_ctx(url, self.cfg())
            await http_security.HttpSecurityModule({}).run(ctx_home)
            params = await vulnerability_indicators.VulnerabilityIndicatorModule()._discover_params(ctx_home)
            self.assertIn("display", params)
            self.assertNotIn("amp;display", params)
            await ctx_home.http.aclose()

    async def test_reconnaissance_module_checks(self):
        from core.http_client import Fetched
        from modules.reconnaissance import ReconnaissanceModule

        cfg = self.cfg()
        ctx = make_ctx("http://127.0.0.1:8000/", cfg)
        ctx.homepage = Fetched(
            "http://127.0.0.1:8000/",
            200,
            {"content-type": "text/html"},
            (
                '<html><head>'
                '<script src="https://cdn.example.net/bundle.js"></script>'
                '<script src="/app.js"></script>'
                '</head><body>'
                '<form><input type="file" name="avatar"></form>'
                '<script>'
                'localStorage.setItem("access_token", "xyz");'
                'document.getElementById("out").innerHTML = location.hash;'
                '</script>'
                '</body></html>'
            ),
            1.0,
        )

        async def fake_request(method, u, **kw):
            if u.endswith("/robots.txt"):
                return Fetched(u, 200, {"content-type": "text/plain"}, "User-agent: *\nDisallow: /admin/backup\nSitemap: http://127.0.0.1:8000/sitemap.xml\n", 1.0)
            if u.endswith("/sitemap.xml"):
                return Fetched(u, 200, {"content-type": "application/xml"}, "<urlset><url><loc>http://127.0.0.1:8000/api/v1/users?id=1</loc></url></urlset>", 1.0)
            if u.endswith("/app.js.map"):
                return Fetched(u, 200, {"content-type": "application/json"}, '{"version":3,"sources":["src/index.ts"],"mappings":"AAAA"}', 1.0)
            return Fetched(u, 404, {}, "", 1.0)

        ctx.http.request = fake_request
        out = await ReconnaissanceModule().run(ctx)
        titles = " | ".join(f.title for f in out)
        self.assertIn("robots.txt", titles)
        self.assertIn("Subresource Integrity", titles)
        self.assertIn("File upload", titles)
        self.assertIn("Web Storage", titles)
        self.assertIn("DOM sources", titles)
        self.assertIn("source map", titles.lower())
        await ctx.http.aclose()

    async def test_source_code_and_local_dependency_audit(self):
        import tempfile
        from modules.dependency_audit import audit_local_dependencies
        from modules.source_code import audit_source_directory

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            tmp = Path(d)
            sample_py = tmp / "app_sample.py"
            sample_py.write_text(
                "import hashlib, subprocess, yaml\n"
                "DEBUG = True\n"
                "AWS_KEY = 'AKIAIOSFODNN7PRODKEY'\n"
                "def run_unsafe(user_input, cmd):\n"
                "    eval(user_input)\n"
                "    subprocess.Popen(cmd, shell=True)\n"
                "    yaml.load(user_input)\n"
                "    return hashlib.md5(b'abc').hexdigest()\n",
                encoding="utf-8",
            )
            req_txt = tmp / "requirements.txt"
            req_txt.write_text("pyyaml==5.3.1\nrequests\n", encoding="utf-8")

            sast_findings = audit_source_directory(tmp)
            sast_titles = " | ".join(f.title for f in sast_findings)
            self.assertIn("eval", sast_titles)
            self.assertIn("shell=True", sast_titles)
            self.assertIn("yaml.load", sast_titles)
            self.assertIn("md5", sast_titles.lower())
            self.assertIn("Debug mode", sast_titles)
            self.assertIn("AWS Access Key", sast_titles)
            # Ensure actual secret value is masked in evidence
            for f in sast_findings:
                self.assertNotIn("AKIAIOSFODNN7PRODKEY", f.evidence)

            dep_findings = audit_local_dependencies(tmp)
            dep_titles = " | ".join(f.title for f in dep_findings)
            self.assertIn("CVE-2020-14343", " | ".join(f.cve or "" for f in dep_findings))
            self.assertIn("Unpinned dependency", dep_titles)

    async def test_api_security_owasp_top10_2023(self):
        from core.http_client import Fetched
        from modules.api_security import ApiSecurityModule

        cfg = self.cfg()
        ctx = make_ctx("http://127.0.0.1:8000/api/v1/checkout/42?api_key=abcdef123456&limit=500&callback_url=https://example.org/cb", cfg)
        ctx.homepage = Fetched(
            ctx.target.url,
            200,
            {"content-type": "application/json"},
            '{"id": 42, "username": "alice", "password_hash": "$2b$12$xyz", "admin_endpoint": "/api/v1/admin/users"}',
            1.0,
        )

        async def fake_request(method, u, **kw):
            if u.endswith("/openapi.json"):
                return Fetched(
                    u,
                    200,
                    {"content-type": "application/json"},
                    '{"openapi": "3.0.0", "paths": {"/api/v1/users/{id}": {"get": {"responses": {"200": {}}}}}}',
                    1.0,
                )
            return Fetched(u, 404, {"content-type": "application/json"}, '{"status": 404}', 1.0)

        ctx.http.request = fake_request
        out = await ApiSecurityModule().run(ctx)
        owasp_refs = " | ".join(f.owasp_reference for f in out)
        self.assertIn("API1:2023", owasp_refs)
        self.assertIn("API2:2023", owasp_refs)
        self.assertIn("API3:2023", owasp_refs)
        self.assertIn("API4:2023", owasp_refs)
        self.assertIn("API5:2023", owasp_refs)
        self.assertIn("API6:2023", owasp_refs)
        self.assertIn("API7:2023", owasp_refs)
        self.assertIn("API9:2023", owasp_refs)
        await ctx.http.aclose()


if __name__ == "__main__":
    unittest.main(verbosity=2)