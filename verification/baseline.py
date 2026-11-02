"""Phase 0: Baseline Calibration & Soft-404 Verification Gate.

Per-host, before anything:
1. 3 random 8-char paths.
2. Record status, length, md5 of normalized body, and content-type.
3. Classify soft-404 when md5 matches or status matches and abs(len - base) < max(80, 1%).
4. Path is REAL only if the body matches that path's own content signature.
5. If the 3 baselines vary > 25%, mark calibration unstable and downgrade every path finding one level.
6. SPA fingerprint -> all path probes on that host start at INFO unless signature matches.
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from typing import Any

from core.finding import CRITICAL, HIGH, INFO, LOW, MEDIUM
from net.client import HttpClientWrapper, fetch
from probe.soft404 import (
    CONTENT_SIGNATURES,
    SPA_FINGERPRINTS,
    BaselineSample,
    Soft404Baseline,
    body_md5,
    detect_spa_markers,
    downgrade_one_level,
    evaluate_path_probe,
    is_soft404,
    matches_content_signature,
    normalize_body,
)

logger = logging.getLogger("tsmss.verification.baseline")


@dataclass
class HostBaseline:
    host: str
    baseline: Soft404Baseline
    is_spa: bool = False
    unstable: bool = False
    samples: list[BaselineSample] = field(default_factory=list)

    def evaluate_path(
        self,
        path: str,
        status: int,
        body: str,
        default_severity: str = MEDIUM,
        no_soft404: bool = False,
    ) -> tuple[bool, str, str]:
        """Evaluate a probed path against this host's baseline and signature rules."""
        return evaluate_path_probe(
            path=path,
            status=status,
            body=body,
            default_severity=default_severity,
            baseline=self.baseline,
            no_soft404=no_soft404,
        )


async def calibrate_host(
    base_url: str,
    client: HttpClientWrapper | None = None,
    num_probes: int = 3,
) -> HostBaseline:
    """Run Phase 0 baseline calibration against *base_url* using 3 random paths."""
    base_clean = base_url.rstrip("/")
    samples: list[BaselineSample] = []
    spa_detected = False

    for _ in range(max(1, num_probes)):
        rand_token = secrets.token_hex(4)
        rand_path = f"/tsmss_{rand_token}"
        probe_url = f"{base_clean}{rand_path}"

        fetched = await fetch(probe_url, client=client, timeout=10.0)
        body = fetched.body or ""
        md5 = body_md5(body)

        if not spa_detected and detect_spa_markers(body):
            spa_detected = True

        samples.append(
            BaselineSample(
                path=rand_path,
                status=fetched.status,
                length=len(body),
                md5=md5,
                content_type=fetched.headers.get("content-type", ""),
            )
        )

    lengths = [s.length for s in samples]
    min_len = min(lengths) if lengths else 0
    max_len = max(lengths) if lengths else 0
    statuses = {s.status for s in samples}

    unstable = False
    if len(lengths) > 1 and min_len > 0:
        spread = (max_len - min_len) / float(min_len)
        if spread > 0.25:
            unstable = True
    elif len(statuses) > 1:
        unstable = True

    calibration_tag = "unstable" if unstable else "stable"
    baseline = Soft404Baseline(
        samples=samples,
        calibration=calibration_tag,
        is_spa=spa_detected,
        spa_markers=sorted(SPA_FINGERPRINTS.keys()) if spa_detected else [],
    )

    logger.info(
        "Host baseline calibrated for %s: %s (SPA=%s, samples=%d)",
        base_clean,
        calibration_tag,
        spa_detected,
        len(samples),
    )

    return HostBaseline(
        host=base_clean,
        baseline=baseline,
        is_spa=spa_detected,
        unstable=unstable,
        samples=samples,
    )
