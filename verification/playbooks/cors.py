"""Phase 3 Playbook: CORS Misconfiguration Verification.

Probes:
  `Origin: https://evil.example`
  `Origin: null`
  `Origin: https://<target>.evil.example`

Oracle:
  Access-Control-Allow-Origin (ACAO) reflects evil origin AND
  Access-Control-Allow-Credentials (ACAC) is "true" -> HIGH.
  Wildcard (*) without credentials -> LOW.
"""
from __future__ import annotations

import logging

from core.finding import HIGH, LOW
from verification.doctrine import CONFIRMED, CTX_HEADER, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.cors")


def evaluate_cors_response(
    headers: dict[str, str],
    probe_origin: str = "https://evil.example",
) -> tuple[bool, str, str]:
    """Verify CORS misconfiguration oracle. Returns (confirmed, severity, reason)."""
    hdrs = {k.lower(): str(v).strip() for k, v in headers.items()}
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "").lower() == "true"

    if not acao:
        return False, "", "No Access-Control-Allow-Origin header present"

    # Insecure reflection + credentials
    if (acao == probe_origin or acao == "null") and acac:
        return True, HIGH, f"CORS reflects arbitrary origin ({acao}) with credentials enabled"

    if acao == "*":
        return True, LOW, "Wildcard Access-Control-Allow-Origin without credentials"

    if probe_origin in acao and not acac:
        return True, LOW, f"CORS reflects arbitrary origin ({acao}) without credentials"

    return False, "", f"Origin not accepted or properly restricted ({acao})"
