"""Phase 3 Playbook: Web Cache Deception & IDOR Verification.

Web Cache Deception:
  Probes: `/account/zz.css`, `/profile/zz.js`, `/zz.jpg`
  Oracle: 200 with dynamic HTML body AND public cache headers (`public`, `max-age > 0`, `X-Cache: HIT`).
  Then unauthenticated request fetches the identical private content.

IDOR:
  Probes: numeric / UUID resource identifiers mutated (±1, adjacent ID).
  Oracle: Status 200 with distinct identity data disclosed without authorization failure.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from core.finding import HIGH, MEDIUM
from verification.doctrine import CONFIRMED, CTX_UNKNOWN, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.cache_deception")


def evaluate_cache_deception(
    headers: dict[str, str],
    body: str,
    baseline_private_body: str,
) -> tuple[bool, str]:
    """Verify web cache deception oracle."""
    hdrs = {k.lower(): str(v).lower() for k, v in headers.items()}
    cc = hdrs.get("cache-control", "")
    xcache = hdrs.get("x-cache", "")

    # Look for cache headers
    is_cached = "public" in cc or "max-age" in cc or "hit" in xcache
    # Ensure it's not a generic 404/static file
    has_html_content = "<html" in body.lower() or "<body" in body.lower()
    matches_private = (body == baseline_private_body) or (len(body) > 100 and abs(len(body) - len(baseline_private_body)) < 50)

    if is_cached and has_html_content and matches_private:
        return True, f"Dynamic private HTML response cached by edge/proxy (Cache-Control: {cc}, X-Cache: {xcache})"
    return False, "Response was not cached or does not leak private session content"


def evaluate_idor_mutation(
    orig_status: int,
    orig_body: str,
    mutated_status: int,
    mutated_body: str,
    id_marker: str,
) -> tuple[bool, str]:
    """Verify IDOR oracle: mutated resource ID returns a distinct 200 record without authorization denial."""
    if orig_status == 200 and mutated_status == 200:
        if orig_body != mutated_body and len(mutated_body) > 20:
            if "unauthorized" not in mutated_body.lower() and "login" not in mutated_body.lower():
                return True, f"Distinct authorized record retrieved for mutated resource identifier ({id_marker})"
    return False, "Mutated ID was rejected or returned identical response"
