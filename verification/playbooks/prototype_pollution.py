"""Phase 3 Playbook: Client-Side Prototype Pollution Verification.

Probes:
  `?__proto__[zz]=1`
  `?constructor[prototype][zz]=1`
  JSON body variant

Oracle:
  Browser subagent evaluates `({}).zz === 1` or property existence on Object.prototype.
"""
from __future__ import annotations

import logging
from typing import Any

from core.finding import MEDIUM
from verification.doctrine import CONFIRMED, CTX_UNKNOWN, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.prototype_pollution")


def evaluate_prototype_pollution_proof(eval_result: Any, token_key: str = "zz") -> tuple[bool, str]:
    """Verify prototype pollution oracle from browser JS execution."""
    if eval_result is True or eval_result == 1 or str(eval_result) == "1":
        return True, f"Object.prototype polluted: ({{}}).{token_key} === 1 confirmed in JS runtime"
    return False, "Prototype property was not polluted"
