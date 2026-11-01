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
from modules import (cookies, cors, headers, http_security, information_disclosure,
                     vulnerability_indicators)

PAGE = b"""<html><head><title>fixture</title></head><body>
<h1>hi</h1><a href="/echo?q=1">x</a>
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
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/echo":
            q = qs.get("q", [""])[0]
            if q == "boom'":
                return self._send(500, b"SQL syntax error near '''")
            return self._send(200, f"<html><body>echo: {q}</body></html>".encode())
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


def make_ctx(url, config):
    scope = ScopeGuard([], allow_private=True)
    limiter = RateLimiter(20, 20)

    class FakeHttp:
        def __init__(self):
            import httpx
            self.c = httpx.AsyncClient(follow_redirects=False)
            self.scope = scope

        async def request(self, method, u, retry=True, allow_redirects=False, **kw):
            from core.http_client import Fetched, Hop
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
                    rr = await self.c.request("GET", nxt)
                    status, hdrs = rr.status_code, dict(rr.headers)
                    r = rr
            return Fetched(u, r.status_code, {k.lower(): v for k, v in r.headers.items()},
                           r.text, 1.0, hops=hops, final_url=str(r.url),
                           set_cookies=r.headers.get_list("set-cookie"))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)