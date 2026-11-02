"""Phase 3 Playbook: JWT Vulnerability Verification.

Probes:
  - `alg: none`
  - HMAC-SHA256 signature verification with RSA public key
  - `kid` path traversal (`../../../../dev/null`)
  - `jku` / `x5u` attacker host injection

Oracle:
  Server accepts modified token and the tampered claim (e.g. role: admin) is honoured.
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

from core.finding import HIGH, MEDIUM
from verification.doctrine import CONFIRMED, CTX_UNKNOWN, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.jwt")


def b64url_decode(segment: str) -> bytes:
    """Decode base64url segment with padding."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment)


def parse_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Parse JWT into header, payload, and signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure")
    header = json.loads(b64url_decode(parts[0]).decode("utf-8", "ignore"))
    payload = json.loads(b64url_decode(parts[1]).decode("utf-8", "ignore"))
    return header, payload, parts[2]


def evaluate_jwt_response(status: int, body: str, tampered_claim: str = "admin") -> tuple[bool, str]:
    """Verify whether tampered JWT was honoured."""
    if status in (200, 201) and (tampered_claim in body or "Welcome" in body):
        return True, f"Server accepted tampered JWT (claim '{tampered_claim}' honoured)"
    return False, "Server rejected tampered JWT (401/403 or claim ignored)"
