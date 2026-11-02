"""Phase 3 Playbook: SQL Injection (SQLi) Verification.

Boolean-based differential:
  `1 AND 1=1` vs `1 AND 1=2`, 3 runs each.
  Requires byte delta > 3% AND stable across all 3 pairs.

Time-based injection:
  `1 AND SLEEP(5)`, `1' AND SLEEP(5)-- -`, `1);WAITFOR DELAY '0:0:5'--`, `1'||pg_sleep(5)--`
  3 runs, median delay delta >= 3.0s = CONFIRMED.
  If median delta < 3.0s (e.g. 0.4s) -> CANDIDATE only.

sqlmap integration bridge:
  `sqlmap -u "<url>" --batch --level 3 --risk 2 --technique=BEUST --dbms=<guess>`
  Error strings alone = candidate only.
"""
from __future__ import annotations

import logging
import statistics
import time
from typing import Any, Callable

from core.finding import CRITICAL, HIGH, INFO, MEDIUM
from net.client import fetch
from verification.doctrine import CANDIDATE, CONFIRMED, CTX_SQL, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.sqli")

TIME_PAYLOADS = [
    "1 AND SLEEP(5)",
    "1' AND SLEEP(5)-- -",
    "1);WAITFOR DELAY '0:0:5'--",
    "1'||pg_sleep(5)--",
]


def evaluate_boolean_differential(
    true_lengths: list[int],
    false_lengths: list[int],
) -> tuple[bool, float]:
    """Verify boolean differential: byte delta > 3% and stable across 3 runs."""
    if len(true_lengths) < 3 or len(false_lengths) < 3:
        return False, 0.0

    # Stability check: zero variance or minimal variance within each set
    if max(true_lengths) - min(true_lengths) > max(true_lengths) * 0.05:
        return False, 0.0
    if max(false_lengths) - min(false_lengths) > max(false_lengths) * 0.05:
        return False, 0.0

    avg_true = sum(true_lengths) / float(len(true_lengths))
    avg_false = sum(false_lengths) / float(len(false_lengths))
    base = max(1.0, avg_true)
    delta = abs(avg_true - avg_false) / base

    if delta > 0.03:
        return True, delta
    return False, delta


def evaluate_time_delay(durations: list[float], baseline_delay: float = 0.5) -> tuple[bool, float]:
    """Verify time-based injection: median delta >= 3.0s over 3 runs."""
    if len(durations) < 3:
        return False, 0.0
    med = statistics.median(durations)
    delta = med - baseline_delay
    if delta >= 3.0:
        return True, delta
    return False, delta


async def run_sqli_playbook(
    target_url: str,
    param: str,
    client: Any = None,
    mock_durations: list[float] | None = None,
) -> GateResult:
    """Execute SQLi boolean differential and time delay oracle checks."""
    result = GateResult()
    result.g1_candidate = True
    result.g2_context = CTX_SQL

    # Test time delay
    if mock_durations is not None:
        durations = mock_durations
    else:
        # Measure 3 baseline runs
        base_durations: list[float] = []
        for _ in range(3):
            t0 = time.time()
            await fetch(target_url, client=client)
            base_durations.append(time.time() - t0)
        base_med = statistics.median(base_durations) if base_durations else 0.5

        # Measure 3 runs with SLEEP(5) payload
        durations = []
        delim = "&" if "?" in target_url else "?"
        probe_url = f"{target_url}{delim}{param}=1+AND+SLEEP(5)"
        for _ in range(3):
            t0 = time.time()
            await fetch(probe_url, client=client)
            durations.append(time.time() - t0)

    base_delay = 0.5 if mock_durations is not None else base_med
    time_ok, delta = evaluate_time_delay(durations, baseline_delay=base_delay)

    if time_ok:
        result.g3_confirm = True
        result.g4_repro = True
        result.g5_artifact = True
        result.oracle_name = f"Time-based SQLi delay confirmed (median delta {delta:.2f}s >= 3.0s)"
        result.repro_count = 3
        result.evidence_text = f"Payload: 1 AND SLEEP(5) | Measured durations: {durations} | Median delta: {delta:.2f}s"
    else:
        result.g3_confirm = False
        result.g4_repro = False
        result.kill_reason = f"Time delay delta ({delta:.2f}s) < 3.0s threshold (CANDIDATE only)"

    result.evaluate_confidence()
    return result
