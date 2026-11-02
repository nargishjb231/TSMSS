"""Retry-hardened HTTP and TLS fetch helpers (Work Item D)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import inspect
import random
import time
from typing import Any, Callable

from core.finding import CONFIRMED, HIGH, Finding
from paths import validate_response_body

BACKOFF_STEPS: tuple[float, ...] = (1.0, 3.0)
RETRYABLE_STATUS: set[int] = {408, 429, 500, 502, 503, 504}


def should_retry_status(status: int) -> bool:
    """Return True for 408, 429, and 5xx (including 502/503/504); False for other 4xx."""
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


def compute_backoff(
    attempt: int,
    backoff_base: float = 1.6,
    retry_after: str | None = None,
    max_wait: float = 30.0,
) -> float:
    """D1: Backoff 1s / 3s with 0-400ms jitter, honouring Retry-After when present."""
    parsed = parse_retry_after(retry_after)
    if parsed is not None:
        return min(parsed, max_wait)
    step = BACKOFF_STEPS[attempt] if attempt < len(BACKOFF_STEPS) else BACKOFF_STEPS[-1]
    if backoff_base < 1.0:
        step = step * max(0.05, backoff_base)
    jitter = random.uniform(0.0, 0.4)
    return min(step + jitter, max_wait)


def _needs_retry(result: Any) -> tuple[bool, str | None]:
    """Inspect a Fetched-like or dict-like result to see if it should be retried."""
    if result is None:
        return True, None
    if isinstance(result, dict):
        err = result.get("error")
        if err and result.get("retryable", True):
            return True, None
        return False, None
    status = getattr(result, "status", 0)
    err = getattr(result, "error", None)
    body = getattr(result, "body", "")
    headers = getattr(result, "headers", {}) or {}
    if err is not None:
        return True, None
    if should_retry_status(status):
        ra = headers.get("retry-after") if isinstance(headers, dict) else None
        return True, ra
    ok_body, _ = validate_response_body(body, headers, status, "GET", None)
    if not ok_body:
        return True, None
    return False, None


async def fetch(
    op: Callable[..., Any],
    *,
    attempts: int = 3,
    backoff_base: float = 1.6,
    sleep_fn: Callable[[float], Any] = asyncio.sleep,
) -> Any:
    """Execute async callable *op* with up to *attempts* (default 3) tries (D1).

    Retries on timeout, connection reset, 0-byte body, and 502/503/504 (plus 408/429).
    """
    total = max(1, int(attempts))
    last_exc: Exception | None = None
    last_res: Any = None
    takes_attempt = False
    try:
        sig = inspect.signature(op)
        takes_attempt = len(sig.parameters) >= 1
    except (ValueError, TypeError):
        takes_attempt = False

    for attempt in range(total):
        try:
            res = await (op(attempt) if takes_attempt else op())
            last_res = res
            retry_needed, ra = _needs_retry(res)
            if not retry_needed or attempt + 1 >= total:
                return res
            wait = compute_backoff(attempt, backoff_base=backoff_base, retry_after=ra)
            await sleep_fn(wait)
        except (TimeoutError, asyncio.TimeoutError, ConnectionResetError, OSError) as exc:
            last_exc = exc
            if attempt + 1 >= total:
                break
            wait = compute_backoff(attempt, backoff_base=backoff_base)
            await sleep_fn(wait)

    if last_res is not None:
        return last_res
    if last_exc is not None:
        raise last_exc
    return None


def fetch_sync(
    op: Callable[..., Any],
    *,
    attempts: int = 3,
    backoff_base: float = 1.6,
    sleep_fn: Callable[[float], Any] = time.sleep,
) -> Any:
    """Synchronous 3-attempt retry helper for blocking TLS socket handshakes (D1)."""
    total = max(1, int(attempts))
    last_exc: Exception | None = None
    last_res: Any = None
    takes_attempt = False
    try:
        sig = inspect.signature(op)
        takes_attempt = len(sig.parameters) >= 1
    except (ValueError, TypeError):
        takes_attempt = False

    for attempt in range(total):
        try:
            res = op(attempt) if takes_attempt else op()
            last_res = res
            retry_needed, ra = _needs_retry(res)
            if not retry_needed or attempt + 1 >= total:
                return res
            wait = compute_backoff(attempt, backoff_base=backoff_base, retry_after=ra)
            sleep_fn(wait)
        except (TimeoutError, ConnectionResetError, OSError) as exc:
            last_exc = exc
            if attempt + 1 >= total:
                break
            wait = compute_backoff(attempt, backoff_base=backoff_base)
            sleep_fn(wait)

    if last_res is not None:
        return last_res
    if last_exc is not None:
        raise last_exc
    return None


def make_unreachable_finding(url: str, error_detail: str = "") -> Finding:
    """Create the single HIGH TARGET_UNREACHABLE finding when all 3 attempts fail (D2)."""
    return Finding(
        target=url,
        url=url,
        category="Availability & Reachability",
        title="TARGET_UNREACHABLE",
        severity=HIGH,
        cwe="CWE-400",
        description=(
            "All 3 connection attempts to the target failed (timeout, connection reset, "
            "or empty response). Security checks could not be completed and the target "
            "is marked INCOMPLETE."
        ),
        evidence=f"Target: {url}\nAttempts: 3/3 failed\nLast error: {error_detail or 'unreachable'}",
        detection_method="3-attempt retry probe (backoff 1s/3s + jitter)",
        confidence=CONFIRMED,
        remediation="Verify target availability, DNS resolution, and network reachability before rescanning.",
        module="net.client",
        tags=["unreachable", "incomplete"],
    )
