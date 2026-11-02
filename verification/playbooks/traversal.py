"""Phase 3 Playbook: Path Traversal / LFI Verification.

Probes:
  `../../../../etc/passwd`, `..%2f..%2f..%2f`, `....//`, `%252e%252e%252f`

Oracle:
  `root:x:0:0` in response body (Linux) or `[extensions]` / `for 16-bit app support` (Windows win.ini).
"""
from __future__ import annotations

import logging
import re

from core.finding import HIGH
from verification.doctrine import CONFIRMED, CTX_TEXT, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.traversal")

PASSWD_RE = re.compile(r"root:[x*]:0:0:")
WIN_INI_RE = re.compile(r"\[extensions\]|for 16-bit app support", re.I)


def evaluate_traversal_body(body: str) -> tuple[bool, str]:
    """Verify Path Traversal oracle in body."""
    if PASSWD_RE.search(body):
        return True, "Linux /etc/passwd root account entry observed in body (root:x:0:0)"
    if WIN_INI_RE.search(body):
        return True, "Windows system win.ini section observed in body ([extensions])"
    return False, "No system file signature observed in response body"
