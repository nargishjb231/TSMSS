"""Doctrine: The Five-Gate Verification Standard and Kill Rules.

DOCTRINE — five gates. A finding must pass all five or it dies:
G1 CANDIDATE  payload sent, response differs from baseline
G2 CONTEXT    injection context determined and named (MARKUP / ATTR_Q / ATTR_UQ /
              JS_STRING / JSON / COMMENT / TEXT / SQL / TEMPLATE / HEADER)
G3 CONFIRM    class-specific oracle fires (DOM proof, time delta, OOB callback,
              engine output, byte diff, redirect hop)
G4 REPRO      3 consecutive runs, identical verdict, on a clean session
G5 ARTIFACT   request + response + screenshot/recording/hash stored

CONFIDENCE:
CONFIRMED  - all five gates passed, artifact present
LIKELY     - G1-G3 passed, G4 unstable
CANDIDATE  - G1-G2 only
Only CONFIRMED counts in the score. CANDIDATE caps at INFO.

KILL RULES — drop immediately:
- byte-identical response
- reflection only in JS string / JSON with no sink
- soft-404 match
- edge-challenge body (unless browser subagent got through)
- oracle fires once in five runs
- 200 with empty body and no Content-Length: 0
- payload reflected but HTML-entity double-encoded with no decode
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.finding import CRITICAL, HIGH, INFO, LOW, MEDIUM, Finding

# Confidence levels
CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
CANDIDATE = "CANDIDATE"

# Context types
CTX_MARKUP = "MARKUP"
CTX_ATTR_Q = "ATTR_Q"
CTX_ATTR_UQ = "ATTR_UQ"
CTX_JS_STRING = "JS_STRING"
CTX_JSON = "JSON"
CTX_COMMENT = "COMMENT"
CTX_TEXT = "TEXT"
CTX_SQL = "SQL"
CTX_TEMPLATE = "TEMPLATE"
CTX_HEADER = "HEADER"
CTX_UNKNOWN = "UNKNOWN"


@dataclass
class GateResult:
    g1_candidate: bool = False
    g2_context: str = CTX_UNKNOWN
    g3_confirm: bool = False
    g4_repro: bool = False
    g5_artifact: bool = False
    oracle_name: str = ""
    repro_count: int = 0
    confidence: str = CANDIDATE
    killed: bool = False
    kill_reason: str = ""
    evidence_text: str = ""
    request_dump: str = ""
    response_slice: str = ""
    response_hash: str = ""
    artifact_paths: list[str] = field(default_factory=list)

    def evaluate_confidence(self) -> str:
        """Evaluate confidence based on five gates."""
        if self.killed:
            self.confidence = CANDIDATE
            return self.confidence
        if self.g1_candidate and self.g2_context != CTX_UNKNOWN and self.g3_confirm and self.g4_repro and self.g5_artifact:
            self.confidence = CONFIRMED
        elif self.g1_candidate and self.g2_context != CTX_UNKNOWN and self.g3_confirm:
            self.confidence = LIKELY
        else:
            self.confidence = CANDIDATE
        return self.confidence


def check_kill_rules(
    status: int,
    body: str,
    baseline_body: str | None = None,
    is_soft404: bool = False,
    is_edge_challenge: bool = False,
    context: str = CTX_UNKNOWN,
    has_sink: bool = False,
    double_encoded: bool = False,
    oracle_success_ratio: float | None = None,
    content_length_zero_valid: bool = True,
) -> tuple[bool, str]:
    """Evaluate doctrine Kill Rules. Returns (should_kill, reason)."""
    # 1. 200 with empty body and no Content-Length: 0
    if status == 200 and len(body) == 0 and not content_length_zero_valid:
        return True, "kill: 200 with 0-byte body without Content-Length: 0"

    # 2. Byte-identical response to baseline
    if baseline_body is not None and body == baseline_body:
        return True, "kill: byte-identical response to baseline (no candidate difference)"

    # 3. Soft-404 match
    if is_soft404:
        return True, "kill: soft-404 match"

    # 4. Edge-challenge body
    if is_edge_challenge:
        return True, "kill: edge-challenge response (app not observed)"

    # 5. Reflection only in JS string / JSON with no sink
    if context in (CTX_JS_STRING, CTX_JSON) and not has_sink:
        return True, f"kill: reflection inside {context} without actionable sink"

    # 6. Payload reflected but HTML-entity double-encoded with no decode
    if double_encoded:
        return True, "kill: payload reflected but HTML-entity double-encoded with no decode"

    # 7. Oracle fires once in five runs (unstable/flaky < 60%)
    if oracle_success_ratio is not None and oracle_success_ratio < 0.6:
        return True, f"kill: oracle flaky ({oracle_success_ratio:.1%} success rate, requires 3/3)"

    return False, ""
