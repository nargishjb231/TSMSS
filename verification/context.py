"""Phase 2: Candidate Generation & Context Classification.

Walks back 400 characters to determine the exact reflection context:
- inside <script> and not past </script> -> JS_STRING
- only present as \\u003c/\\u003e/\\x3c/\\x3e -> JS_STRING
- inside a quoted attr -> ATTR_Q / ATTR_UQ
- inside <!-- --> -> COMMENT
- between tags -> MARKUP
- reflected only in JSON body -> JSON

Hardcoded traps:
1. Next.js RSC flight data: `self.__next_f.push([1,"..."])` is a JS string.
2. `__N_SSP` / `__NEXT_DATA__` query echo is JSON.
3. JSON-LD and schema.org echoes are often double-encoded (`&quot;&gt;&lt;b&gt;`).
4. Param produces zero reflection (byte-identical body) -> not a candidate.
"""
from __future__ import annotations

import html
import json
import logging
import re
import secrets
from dataclasses import dataclass
from typing import Any

from core.finding import CRITICAL, HIGH, INFO, LOW, MEDIUM
from probe.context import (
    classify as base_classify,
    evaluate_xss_outcome,
    locate_and_classify,
)
from verification.doctrine import (
    CTX_ATTR_Q,
    CTX_ATTR_UQ,
    CTX_COMMENT,
    CTX_HEADER,
    CTX_JS_STRING,
    CTX_JSON,
    CTX_MARKUP,
    CTX_SQL,
    CTX_TEMPLATE,
    CTX_TEXT,
    CTX_UNKNOWN,
)

logger = logging.getLogger("tsmss.verification.context")

# Actionable DOM sinks that allow promotion of JS_STRING / JSON
SINK_PATTERNS = re.compile(
    r"""(?i)\b(dangerouslySetInnerHTML|innerHTML\s*=|document\.write\s*\(|v-html|eval\s*\(|new\s+Function\s*\()|\{!!\s*[\w\.\$]+\s*!!\}"""
)

# Traps
NEXT_RSC_PATTERN = re.compile(r"""self\.__next_f\.push\(\[\s*\d+\s*,\s*\"""")
NEXT_DATA_PATTERN = re.compile(r"""<(?:script)[^>]*id=["']__NEXT_DATA__["'][^>]*>""")
JSON_LD_PATTERN = re.compile(r"""<(?:script)[^>]*type=["']application/ld\+json["'][^>]*>""")


@dataclass
class CandidateContext:
    token: str
    param: str
    context: str
    has_sink: bool
    sink_match: str
    is_next_rsc: bool
    is_next_data: bool
    is_json_ld_encoded: bool
    is_double_encoded: bool
    severity_floor: str
    is_candidate: bool
    raw_window: str


def generate_probe_token() -> str:
    """Generate a token-unique harmless payload: zz<8hex>."""
    return f"zz{secrets.token_hex(4)}"


def analyze_reflection(
    body: str,
    token: str,
    param: str = "",
    baseline_body: str | None = None,
) -> CandidateContext:
    """Analyze reflection of *token* in *body* and classify injection context."""
    # If param produces zero reflection (or byte-identical body) -> not a candidate
    if token not in body:
        # Check for unicode / hex escaped variants
        esc_u = token.replace("<", "\\u003c").replace(">", "\\u003e")
        esc_x = token.replace("<", "\\x3c").replace(">", "\\x3e")
        if esc_u in body or esc_x in body:
            token_match = esc_u if esc_u in body else esc_x
        else:
            return CandidateContext(
                token=token,
                param=param,
                context=CTX_UNKNOWN,
                has_sink=False,
                sink_match="",
                is_next_rsc=False,
                is_next_data=False,
                is_json_ld_encoded=False,
                is_double_encoded=False,
                severity_floor=INFO,
                is_candidate=False,
                raw_window="",
            )
    else:
        token_match = token

    if baseline_body is not None and body == baseline_body:
        return CandidateContext(
            token=token,
            param=param,
            context=CTX_UNKNOWN,
            has_sink=False,
            sink_match="",
            is_next_rsc=False,
            is_next_data=False,
            is_json_ld_encoded=False,
            is_double_encoded=False,
            severity_floor=INFO,
            is_candidate=False,
            raw_window="",
        )

    # Locate token in body
    idx = body.find(token_match)
    if idx == -1:
        idx = body.find(token)
    window_start = max(0, idx - 400)
    window_end = min(len(body), idx + len(token_match) + 400)
    raw_window = body[window_start:window_end]

    # Check for Next.js RSC flight data trap
    is_rsc = bool(NEXT_RSC_PATTERN.search(body[:idx + 100]))
    # Check for Next data JSON trap
    is_next_data = bool(NEXT_DATA_PATTERN.search(body[:idx + 100]))
    # Check for JSON-LD double encoding
    is_json_ld = bool(JSON_LD_PATTERN.search(body[:idx + 100]))
    is_double_encoded = bool("&quot;" in raw_window or "&amp;" in raw_window or "&gt;" in raw_window or "&lt;" in raw_window)

    # Determine context by walking back 400 chars
    walkback = body[max(0, idx - 400):idx]
    lower_wb = walkback.lower()

    if is_rsc or "\\u003c" in token_match or "\\x3c" in token_match:
        context = CTX_JS_STRING
    elif is_next_data or (walkback.rstrip().endswith((":", '":', '",', "[")) and ("{" in walkback or "[" in walkback)):
        context = CTX_JSON
    elif "<script" in lower_wb and "</script>" not in lower_wb:
        context = CTX_JS_STRING
    elif "<!--" in walkback and "-->" not in walkback:
        context = CTX_COMMENT
    else:
        # Check quoted attribute vs markup
        last_open_angle = walkback.rfind("<")
        last_close_angle = walkback.rfind(">")
        if last_open_angle > last_close_angle:
            tag_interior = walkback[last_open_angle:]
            # Check quotes
            dquotes = tag_interior.count('"')
            squotes = tag_interior.count("'")
            if dquotes % 2 == 1 or squotes % 2 == 1:
                context = CTX_ATTR_Q
            elif "=" in tag_interior:
                context = CTX_ATTR_UQ
            else:
                context = CTX_ATTR_UQ
        else:
            # Between tags
            context = CTX_MARKUP

    # Sinks check
    sink_match = ""
    sink_search = SINK_PATTERNS.search(body)
    has_sink = bool(sink_search)
    if has_sink and sink_search:
        sink_match = sink_search.group(0)

    # Severity floor: MARKUP -> HIGH, ATTR_* -> HIGH, JS_STRING/JSON -> INFO unless sink found
    if context in (CTX_MARKUP, CTX_ATTR_Q, CTX_ATTR_UQ):
        severity_floor = HIGH
    elif has_sink:
        severity_floor = HIGH
    else:
        severity_floor = INFO

    return CandidateContext(
        token=token,
        param=param,
        context=context,
        has_sink=has_sink,
        sink_match=sink_match,
        is_next_rsc=is_rsc,
        is_next_data=is_next_data,
        is_json_ld_encoded=is_json_ld,
        is_double_encoded=is_double_encoded,
        severity_floor=severity_floor,
        is_candidate=True,
        raw_window=raw_window,
    )
