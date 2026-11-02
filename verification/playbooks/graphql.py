"""Phase 3 Playbook: GraphQL Security Verification.

Probes:
  - Introspection query (`__schema { types { name } }`)
  - Field suggestion leaks
  - Depth bomb / query complexity
  - Alias overloading / batch query
"""
from __future__ import annotations

import json
import logging
from typing import Any

from core.finding import INFO, LOW, MEDIUM
from verification.doctrine import CONFIRMED, CTX_JSON, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.graphql")


def evaluate_graphql_introspection(body: str) -> tuple[bool, str]:
    """Verify GraphQL introspection oracle."""
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            schema = data.get("data", {}).get("__schema")
            if schema and "types" in schema:
                types_count = len(schema["types"])
                return True, f"GraphQL full schema introspection enabled ({types_count} types disclosed)"
    except Exception:
        pass
    return False, "GraphQL introspection disabled or query rejected"
