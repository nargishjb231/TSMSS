"""Dual token-bucket limiter: global ceiling + per-host politeness."""
from __future__ import annotations

import asyncio
import time


class TokenBucket:
    def __init__(self, rate: float, burst: float | None = None):
        self.rate = max(rate, 0.01)
        self.capacity = max(burst if burst is not None else rate, 1.0)
        self._tokens = self.capacity
        self._stamp = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, cost: float = 1.0) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._stamp) * self.rate)
                self._stamp = now
                if self._tokens >= cost:
                    self._tokens -= cost
                    return
                deficit = cost - self._tokens
            await asyncio.sleep(min(deficit / self.rate, 5.0))


class RateLimiter:
    def __init__(self, global_rps: float, host_rps: float):
        self._global = TokenBucket(global_rps, burst=max(global_rps, 2))
        self._host_rps = max(host_rps, 0.05)
        self._hosts: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def _host_bucket(self, host: str) -> TokenBucket:
        async with self._lock:
            b = self._hosts.get(host)
            if b is None:
                b = self._hosts[host] = TokenBucket(self._host_rps, burst=2)
            return b

    async def acquire(self, host: str) -> None:
        await self._global.acquire()
        await (await self._host_bucket(host)).acquire()

    def backoff_host(self, host: str, seconds: float) -> None:
        b = self._hosts.get(host)
        if b:
            b.rate = max(0.05, min(b.rate, 1.0 / max(seconds, 0.2)))