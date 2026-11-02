"""Phase 3 Playbook: Server-Side Template Injection (SSTI) Verification.

Baseline-diff required (the "49 appears somewhere" trap).
Math probes:
  `{{7*7}}`, `${7*7}`, `#{7*7}`, `*{7*7}`, `<%= 7*7 %>`, `${{7*7}}`, `@(7*7)`

Engine discrimination:
  `{{7*'7'}}` -> 7777777 (Twig/Smarty string repetition) vs 49 (Jinja2 numeric cast).

RCE proof:
  `{{config}}` / `${T(java.lang.Runtime).getRuntime().exec('id')}` or SSTImap integration.
"""
from __future__ import annotations

import logging
from typing import Any

from core.finding import CRITICAL, HIGH, INFO
from net.client import fetch
from verification.doctrine import CONFIRMED, CTX_TEMPLATE, GateResult

logger = logging.getLogger("tsmss.verification.playbooks.ssti")

SSTI_MATH_PROBES = {
    "jinja_twig": "{{7*7}}",
    "freemarker_el": "${7*7}",
    "ruby_erb": "<%= 7*7 %>",
    "ognl": "#{7*7}",
    "spring": "*{7*7}",
    "razor": "@(7*7)",
    "helm": "${{7*7}}",
}


def evaluate_ssti_evaluation(
    probe_body: str,
    baseline_body: str,
    math_result: str = "49",
) -> tuple[bool, str]:
    """Verify that the math result appears as a new reflection (baseline-diff)."""
    # Trap: if '49' already existed on the baseline page, it's not template execution!
    if math_result in baseline_body:
        base_count = baseline_body.count(math_result)
        probe_count = probe_body.count(math_result)
        if probe_count <= base_count:
            return False, "49 already present in baseline (pre-existing literal)"

    if math_result in probe_body:
        return True, f"Expression evaluated to {math_result} (baseline-diff verified)"
    return False, "Evaluation result not found in response"


def discriminate_engine(twig_body: str) -> str:
    """Discriminate template engine: Twig repeats string '7777777', Jinja2 outputs 49."""
    if "7777777" in twig_body:
        return "Twig"
    elif "49" in twig_body:
        return "Jinja2"
    return "Unknown"


async def run_ssti_playbook(
    target_url: str,
    param: str,
    client: Any = None,
) -> GateResult:
    """Execute SSTI verification playbook."""
    result = GateResult()
    result.g1_candidate = True
    result.g2_context = CTX_TEMPLATE

    # 1. Fetch baseline
    base_resp = await fetch(target_url, client=client)
    base_body = base_resp.body or ""

    delim = "&" if "?" in target_url else "?"
    probe_url = f"{target_url}{delim}{param}={{{{7*7}}}}"
    probe_resp = await fetch(probe_url, client=client)
    probe_body = probe_resp.body or ""

    eval_ok, reason = evaluate_ssti_evaluation(probe_body, base_body, "49")
    if not eval_ok:
        result.g3_confirm = False
        result.kill_reason = reason
        result.evaluate_confidence()
        return result

    # 2. Discriminate engine
    twig_url = f"{target_url}{delim}{param}={{{{7*'7'}}}}"
    twig_resp = await fetch(twig_url, client=client)
    engine = discriminate_engine(twig_resp.body or "")

    result.g3_confirm = True
    result.g4_repro = True
    result.g5_artifact = True
    result.oracle_name = f"SSTI mathematical evaluation verified -> Engine: {engine}"
    result.evidence_text = f"Payload: {{{{7*7}}}} -> 49 (baseline-diff confirmed) | Engine probe {{{{7*'7'}}}} -> {engine}"
    result.evaluate_confidence()
    return result
