"""Scope-aware, rate-limited, retrying async HTTP client."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from core.scope import ScopeGuard


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
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def get_all(self, name: str) -> list[str]:
        raw = self.headers.get(name.lower())
        return [raw] if raw else []


_TRANSIENT_STATUS = {429, 500, 502, 503, 504}


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
                fetched = Fetched(url, resp.status_code, headers, body, elapsed,
                                  final_url=str(resp.url))
                if resp.status_code in _TRANSIENT_STATUS and attempt < attempts:
                    await self._honour_retry_after(resp, attempt, host)
                    last = fetched
                    continue
                if allow_redirects:
                    await self._walk_redirects(fetched, headers, attempt, host)
                return fetched
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = Fetched(url, 0, {}, "", 0.0, error=f"{type(exc).__name__}: {exc}")
                if attempt < attempts:
                    await asyncio.sleep(min(2 ** attempt * 0.8, 8))
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
        ra = resp.headers.get("retry-after")
        wait = None
        if ra:
            try:
                wait = float(ra)
            except ValueError:
                wait = None
        if wait is None:
            wait = min(2 ** attempt * 1.5, 20)
        wait = min(wait, 30)
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
                fetched.body = await self._read_body(resp)
            except (httpx.HTTPError, StopRequested) as exc:
                fetched.hops = hops
                fetched.error = f"redirect hop failed: {exc}"
                return
        fetched.hops = hops