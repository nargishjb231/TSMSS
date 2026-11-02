"""Context-aware XSS reflection classifier and two-payload agreement engine (Work Item C)."""
from __future__ import annotations

import re

from core.finding import CONFIRMED, HIGH, INFO, MEDIUM, NEEDS_MANUAL

MARKUP = "MARKUP"
ATTR_SINGLE = "ATTR_SINGLE"
ATTR_DOUBLE = "ATTR_DOUBLE"
ATTR_UNQUOTED = "ATTR_UNQUOTED"
JS_STRING = "JS_STRING"
JSON = "JSON"
COMMENT = "COMMENT"
TEXT = "TEXT"

SINK_PATTERNS = re.compile(
    r"(dangerouslySetInnerHTML|innerHTML\s*=|document\.write\s*\(|v-html\s*=|\{!!\s*.*?\s*!!\})"
)
UNICODE_OR_HEX_ESCAPED_TAG = re.compile(r"(?i)(\\u003[ce]|\\x3[ce]|%3[ce]|&lt;|&gt;)")


def has_dangerous_sink(body: str) -> bool:
    """Return True if *body* contains an explicit dangerous DOM/template sink (C4)."""
    return bool(SINK_PATTERNS.search(body or ""))


def classify(body: str, offset: int) -> str:
    """Classify the syntactic context at *offset* in *body* (C1, C2).

    Returns one of:
    ``MARKUP | ATTR_SINGLE | ATTR_DOUBLE | ATTR_UNQUOTED | JS_STRING | JSON | COMMENT | TEXT``
    """
    if not body or offset < 0 or offset > len(body):
        return TEXT

    prefix_all = body[:offset]
    window = body[max(0, offset - 400): offset]
    window_low = window.lower()

    # 1. HTML comment check: <!-- ... without closing -->
    last_comment_open = prefix_all.rfind("<!--")
    if last_comment_open != -1:
        last_comment_close = prefix_all.rfind("-->")
        if last_comment_close < last_comment_open:
            return COMMENT

    # 2. C2: Walk back 400 chars (and full prefix for large RSC blocks):
    # Inside <script>...</script> and not past </script> -> JS_STRING
    last_script_open_win = window_low.rfind("<script")
    last_script_close_win = window_low.rfind("</script")
    if last_script_open_win != -1 and last_script_open_win > last_script_close_win:
        return JS_STRING

    last_script_open_all = prefix_all.lower().rfind("<script")
    last_script_close_all = prefix_all.lower().rfind("</script")
    if last_script_open_all != -1 and last_script_open_all > last_script_close_all:
        return JS_STRING

    if "self.__next_f.push" in window or "window.__NUXT__" in window:
        return JS_STRING

    # 3. JSON body heuristic
    stripped_body = body.lstrip()
    if stripped_body.startswith(("{", "[")) and not stripped_body.lower().startswith("<!doctype"):
        return JSON

    # 4. Inside an unclosed HTML opening tag <tag attr=...
    last_lt = window.rfind("<")
    last_gt = window.rfind(">")
    if last_lt != -1 and last_lt > last_gt:
        tag_fragment = window[last_lt:]
        # Check attribute context at the end of tag_fragment
        if re.search(r"""=\s*"[^"]*$""", tag_fragment):
            return ATTR_DOUBLE
        if re.search(r"""=\s*'[^']*$""", tag_fragment):
            return ATTR_SINGLE
        if re.search(r"""=\s*[^\s"'<>]*$""", tag_fragment):
            return ATTR_UNQUOTED

    # 5. Check if the reflection at offset starts with an unescaped HTML tag '<'
    at_offset = body[offset: offset + 64]
    if at_offset.startswith("<") and re.match(r"^<[a-zA-Z!/]", at_offset):
        return MARKUP

    return TEXT


def locate_and_classify(body: str, marker: str, raw_tag: str) -> tuple[str, bool, int]:
    """Locate *raw_tag* or *marker* in *body* and return ``(context, survived_unescaped, offset)`` (C2, C3).

    Never URL-decodes the response body before checking tag survival so URL-encoded
    or unicode-escaped reflections inside RSC flight data are classified as ``JS_STRING``.
    """
    if not body:
        return TEXT, False, -1

    # Check if raw unescaped tag is present in the literal body (never URL-decoded)
    raw_idx = body.find(raw_tag)
    if raw_idx != -1:
        ctx_type = classify(body, raw_idx)
        return ctx_type, True, raw_idx

    # C3: Check if marker is present only in escaped form (\u003c, \x3c, %3C, or inside RSC flight data)
    m_idx = body.find(marker)
    if m_idx != -1:
        around = body[max(0, m_idx - 60): min(len(body), m_idx + len(marker) + 60)]
        ctx_type = classify(body, m_idx)
        if re.search(r"(?i)(\\u003[ce]|\\x3[ce]|%3[ce])", around) or ctx_type == JS_STRING:
            return JS_STRING, False, m_idx
        return ctx_type, False, m_idx

    return TEXT, False, -1


def evaluate_xss_outcome(
    ctx_type: str,
    survived_unescaped: bool,
    second_payload_agreed: bool,
    body: str = "",
) -> tuple[str, str]:
    """Deterministic `(severity, confidence)` mapping per C4, C5, C6:
    - MARKUP + survived_unescaped + second_payload_agreed -> (HIGH, CONFIRMED)
    - MARKUP + survived_unescaped (without 2nd agreement) -> (MEDIUM, NEEDS MANUAL VERIFICATION)
    - ATTR_SINGLE / ATTR_DOUBLE / ATTR_UNQUOTED + survived_unescaped -> (HIGH, NEEDS MANUAL VERIFICATION)
    - JS_STRING / JSON -> (INFO, NEEDS MANUAL VERIFICATION) unless unescaped + sink present -> (MEDIUM, NEEDS MANUAL VERIFICATION)
    - COMMENT / TEXT / encoded -> (INFO, NEEDS MANUAL VERIFICATION)
    """
    if ctx_type == MARKUP and survived_unescaped:
        if second_payload_agreed:
            return HIGH, CONFIRMED
        return MEDIUM, NEEDS_MANUAL

    if ctx_type in (ATTR_SINGLE, ATTR_DOUBLE, ATTR_UNQUOTED):
        if survived_unescaped:
            return HIGH, NEEDS_MANUAL
        return INFO, NEEDS_MANUAL

    if ctx_type in (JS_STRING, JSON):
        if survived_unescaped and has_dangerous_sink(body):
            return MEDIUM, NEEDS_MANUAL
        return INFO, NEEDS_MANUAL

    return INFO, NEEDS_MANUAL
