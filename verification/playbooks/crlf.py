"""Phase 3 Playbook: CRLF / HTTP Header Injection Verification.

Probes:
  `%0d%0aSet-Cookie:zz=1`, `%0aSet-Cookie:zz=1`, `%E5%98%8A%E5%98%8D`

Oracle:
  Injected header (`Set-Cookie: zz=1` or custom header) appears in the actual
  HTTP response header block.
"""
from __future__ import annotations

import logging

from core.finding import MEDIUM
from verification.doctrine import CONFIRMED, CTX_HEADER, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.crlf")


def evaluate_crlf_response(headers: dict[str, str], injected_header_name: str = "set-cookie", injected_marker: str = "zz=1") -> tuple[bool, str]:
    """Verify CRLF injection oracle."""
    for k, v in headers.items():
        if k.lower() == injected_header_name.lower() and injected_marker in str(v):
            return True, f"Injected header observed: {k}: {v}"
    return False, "Injected header was not reflected in response headers"
