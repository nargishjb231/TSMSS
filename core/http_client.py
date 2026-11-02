"""Scope-aware, rate-limited, retrying async HTTP client."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import random
from urllib.parse import urljoin, urlsplit

import httpx

from core.scope import ScopeGuard
from paths import validate_response_body


class StopRequested(Exception):
    pass


@dataclass
class Hop:
    url: str
    status: int
    location: str | None = None


@dataclass
class Fetched:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    hops: list[Hop] = field(default_factory=list)
    final_url: str = ""
    truncated: bool = False
    set_cookies: list[str] = field(default_factory=list)
    multi_headers: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        if self.set_cookies and "set-cookie" not in self.multi_headers:
            self.multi_headers["set-cookie"] = list(self.set_cookies)
        elif "set-cookie" in self.multi_headers and not self.set_cookies:
            self.set_cookies = list(self.multi_headers["set-cookie"])

    @property
    def ok(self) -> bool:
        return self.error is None

    def header(self, name: str, default: str = "") -> str:
        val = self.headers.get(name.lower(), default)
        if isinstance(val, list):
            return ", ".join(str(v) for v in val)
        return val

    def get_all(self, name: str) -> list[str]:
        key = name.lower()
        if key in self.multi_headers:
            vals = self.multi_headers[key]
            if key == "set-cookie":
                return list(vals)
            out: list[str] = []
            for v in vals:
                if "," in v:
                    out.extend(p.strip() for p in v.split(",") if p.strip())
                elif v:
                    out.append(v)
            return out
        if key == "set-cookie" and self.set_cookies:
            return list(self.set_cookies)
        raw = self.headers.get(key)
        if not raw:
            return []
        if isinstance(raw, list):
            return [str(v) for v in raw if v]
        if key != "set-cookie" and "," in raw:
            return [p.strip() for p in raw.split(",") if p.strip()]
        return [raw]


def _extract_multi_headers(resp_headers) -> dict[str, list[str]]:
    multi: dict[str, list[str]] = {}
    items = resp_headers.multi_items() if hasattr(resp_headers, "multi_items") else resp_headers.items()
    for k, v in items:
        multi.setdefault(k.lower(), []).append(v)
    return multi


_TRANSIENT_STATUS = {408, 429, 500, 502, 503, 504}


def should_retry_status(status: int) -> bool:
    """Return True only for 408, 429, and 5xx responses; never retry other 4xx."""
    if status in (408, 429):
        return True
    if 500 <= status <= 599:
        return True
    return False


def parse_retry_after(value: str | None) -> float | None:
    """Parse Retry-After header (delta-seconds or RFC 7231 HTTP-date)."""
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        secs = float(raw)
        return max(0.0, secs)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None


def compute_backoff(attempt: int, backoff_base: float = 1.6,
                    retry_after: str | None = None,
                    max_wait: float = 30.0) -> float:
    """Exponential backoff with jitter, honouring Retry-After when present."""
    parsed = parse_retry_after(retry_after)
    if parsed is not None:
        return min(parsed, max_wait)
    exp = (max(1.1, backoff_base) ** attempt) * 0.8
    jitter = random.uniform(0.05, 0.45 * max(1.0, backoff_base))
    return min(exp + jitter, max_wait)


class HttpClient:
    def __init__(self, config, scope: ScopeGuard, limiter, stop_event: asyncio.Event,
                 counter: dict):
        self.config = config
        self.scope = scope
        self.limiter = limiter
        self.stop_event = stop_event
        self.counter = counter
        self.timeout = float(config.get("scan.request_timeout", 20))
        self.max_retries = int(config.get("scan.max_retries", 3))
        self.retry_backoff = float(config.get("scan.retry_backoff", 1.6))
        self.max_redirects = int(config.get("scan.max_redirects", 5))
        self.max_bytes = int(config.get("scan.max_response_bytes", 1_048_576))
        self.delay = float(config.get("scan.delay_between_requests", 0.12))
        self.request_cap = int(config.get("safety.max_total_requests_per_target", 900))
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        limits = httpx.Limits(max_connections=12, max_keepalive_connections=6)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=min(self.timeout, 12)),
            limits=limits, follow_redirects=False, verify=True,
            headers={"User-Agent": self.config.get("scan.user_agent", "TSMSS/1.0"),
                     "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.9",
                     "Accept-Encoding": "gzip, deflate"},
        )
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.aclose()

    def _check_stop(self) -> None:
        if self.stop_event.is_set():
            raise StopRequested()

    def budget_exhausted(self) -> bool:
        return self.counter.get("requests", 0) >= self.request_cap

    async def get(self, url: str, **kwargs) -> Fetched:
        return await self.request("GET", url, **kwargs)

    async def request(self, method: str, url: str, *, allow_redirects: bool = False,
                      retry: bool = True, **kwargs) -> Fetched:
        self._check_stop()
        if self.budget_exhausted():
            return Fetched(url, 0, {}, "", 0.0, error="request budget exhausted")

        host = urlsplit(url).hostname or ""
        attempts = self.max_retries if retry else 0
        last: Fetched | None = None

        for attempt in range(attempts + 1):
            self._check_stop()
            await self.limiter.acquire(host)
            if self.delay:
                await asyncio.sleep(self.delay)
            self.counter["requests"] = self.counter.get("requests", 0) + 1
            started = asyncio.get_event_loop().time()
            try:
                assert self._client is not None
                resp = await self._client.request(method, url, **kwargs)
                elapsed = (asyncio.get_event_loop().time() - started) * 1000
                body = await self._read_body(resp)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                multi = _extract_multi_headers(resp.headers)
                fetched = Fetched(url, resp.status_code, headers, body, elapsed,
                                  final_url=str(resp.url),
                                  set_cookies=resp.headers.get_list("set-cookie"),
                                  multi_headers=multi)
                ok_body, body_err = validate_response_body(
                    body, headers, resp.status_code, method, None
                )
                if not ok_body:
                    fetched.error = body_err
                    if attempt < attempts:
                        wait = compute_backoff(attempt, self.retry_backoff, None, max_wait=12.0)
                        await asyncio.sleep(wait)
                        last = fetched
                        continue
                    return fetched
                if should_retry_status(resp.status_code) and attempt < attempts:
                    await self._honour_retry_after(resp, attempt, host)
                    last = fetched
                    continue
                if allow_redirects:
                    await self._walk_redirects(fetched, headers, attempt, host)
                return fetched
            except (httpx.TimeoutException, httpx.TransportError, ConnectionResetError, OSError) as exc:
                last = Fetched(url, 0, {}, "", 0.0, error=f"{type(exc).__name__}: {exc}")
                if attempt < attempts:
                    wait = compute_backoff(attempt, self.retry_backoff, None, max_wait=12.0)
                    await asyncio.sleep(wait)
                    continue
                return last
            except httpx.HTTPError as exc:
                return Fetched(url, 0, {}, "", 0.0, error=f"{type(exc).__name__}: {exc}")
        return last or Fetched(url, 0, {}, "", 0.0, error="unknown failure")

    async def _read_body(self, resp: httpx.Response) -> str:
        chunks, total, truncated = [], 0, False
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= self.max_bytes:
                truncated = True
                break
        raw = b"".join(chunks)[: self.max_bytes]
        enc = resp.encoding or "utf-8"
        try:
            return raw.decode(enc, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")

    async def _honour_retry_after(self, resp, attempt: int, host: str) -> None:
        ra = resp.headers.get("retry-after") if hasattr(resp, "headers") else None
        wait = compute_backoff(attempt, self.retry_backoff, ra, max_wait=30.0)
        self.limiter.backoff_host(host, wait)
        await asyncio.sleep(wait)

    async def _walk_redirects(self, fetched: Fetched, headers, attempt, host) -> None:
        current, hops = fetched.url, []
        for _ in range(self.max_redirects):
            loc = headers.get("location")
            if not loc or fetched.status not in (301, 302, 303, 307, 308):
                break
            nxt = urljoin(current, loc)
            hops.append(Hop(current, fetched.status, nxt))
            decision = self.scope.check_redirect(current, nxt)
            if not decision.allowed:
                fetched.hops = hops
                fetched.error = f"redirect out of scope: {decision.reason}"
                return
            current = nxt
            try:
                assert self._client is not None
                await self.limiter.acquire(urlsplit(nxt).hostname or "")
                self.counter["requests"] = self.counter.get("requests", 0) + 1
                resp = await self._client.request("GET", nxt)
                fetched.status = resp.status_code
                fetched.final_url = str(resp.url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                fetched.headers = headers
                fetched.multi_headers = _extract_multi_headers(resp.headers)
                fetched.set_cookies = resp.headers.get_list("set-cookie")
                fetched.body = await self._read_body(resp)
            except (httpx.HTTPError, StopRequested) as exc:
                fetched.hops = hops
                fetched.error = f"redirect hop failed: {exc}"
                return
        fetched.hops = hops