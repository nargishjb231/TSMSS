"""Phase 3 Playbook: Host Header Injection Verification.

Probes:
  `X-Forwarded-Host: evil.example`
  `X-Host: evil.example`
  `X-Forwarded-Server: evil.example`
  Absolute-URI request line

Oracle:
  Injected value reflected into response Location, link header, or canonical link tag.
"""
from __future__ import annotations

import logging
import re

from core.finding import MEDIUM
from verification.doctrine import CONFIRMED, CTX_HEADER, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.host_header")


def evaluate_host_header_reflection(
    headers: dict[str, str],
    body: str,
    probe_host: str = "evil.example",
) -> tuple[bool, str]:
    """Verify Host Header injection oracle."""
    hdrs = {k.lower(): str(v) for k, v in headers.items()}
    loc = hdrs.get("location", "")
    if probe_host in loc:
        return True, f"Host reflected into Location header: {loc}"

    link_hdr = hdrs.get("link", "")
    if probe_host in link_hdr:
        return True, f"Host reflected into Link header: {link_hdr}"

    canonical_re = re.compile(rf"""<link\b[^>]*rel=["']canonical["'][^>]*href=["'][^"']*{re.escape(probe_host)}[^"']*["']""", re.I)
    if canonical_re.search(body):
        return True, f"Host reflected into HTML canonical link tag: {probe_host}"

    return False, "Host header value was not reflected into routing or canonical tags"
