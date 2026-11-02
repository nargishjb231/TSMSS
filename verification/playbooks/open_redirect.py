"""Phase 3 Playbook: Open Redirect Verification.

Probes:
  `//evil.example`, `https://evil.example`, `/\\evil.example`, `https:evil.example`, `//evil.example/%2f..`

Oracle:
  HTTP response status in (301, 302, 303, 307, 308) AND
  Location header host != target host (external destination).
  Follow maximum 1 hop.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from core.finding import MEDIUM
from net.client import HttpClientWrapper, fetch
from verification.doctrine import CONFIRMED, CTX_HEADER, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.open_redirect")

REDIRECT_PROBES = [
    "//evil.example",
    "https://evil.example",
    r"/\evil.example",
    "https:evil.example",
    "//evil.example/%2f..",
]


def evaluate_open_redirect(
    status: int,
    location_header: str | None,
    target_host: str,
) -> tuple[bool, str]:
    """Verify open redirect oracle: status is redirect and Location destination is external."""
    if status not in (301, 302, 303, 307, 308) or not location_header:
        return False, "Response is not an HTTP redirect"

    parsed = urlparse(location_header)
    dest_host = parsed.netloc.lower()
    t_host = target_host.lower().split(":")[0]

    if not dest_host:
        # Check scheme-relative or backslash bypasses
        if location_header.startswith("//") or location_header.startswith("/\\"):
            stripped = location_header.lstrip("/\\")
            dest_host = stripped.split("/")[0].split("?")[0].lower()

    if dest_host and dest_host != t_host and not dest_host.endswith(f".{t_host}"):
        return True, f"Redirects to external domain: {dest_host} (Location: {location_header})"
    return False, f"Redirect stays within origin or relative ({location_header})"
