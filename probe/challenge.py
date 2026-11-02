"""WAF/CDN challenge page detection and meta-CSP extraction (Work Item E)."""
from __future__ import annotations

import re

BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
META_CSP_RE = re.compile(
    r"""(?is)<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*content\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>"""
    r"""|<meta\b[^>]*content\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>"""
)

EDGE_BANNER = "EDGE-CHALLENGE (app not observed)"


def extract_title(body: str) -> str:
    """Return lowercased stripped `<title>` text from *body*."""
    if not body:
        return ""
    m = TITLE_RE.search(body)
    return m.group(1).strip() if m else ""


def extract_meta_csp(body: str) -> str:
    """Return the `content` attribute of `<meta http-equiv="content-security-policy">` if present."""
    if not body:
        return ""
    m = META_CSP_RE.search(body)
    if not m:
        return ""
    for g in m.groups():
        if g is not None:
            return g.strip()
    return ""


def detect_challenge(status: int, headers: dict[str, str] | None, body: str) -> tuple[bool, str]:
    """Detect WAF/bot challenge pages (E1).

    Returns ``(is_challenge, provider)`` where provider is one of
    ``"Cloudflare" | "Sucuri" | "Akamai" | "Imperva" | "DataDome" | ""``.
    """
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    text = body or ""
    title = extract_title(text)
    title_low = title.lower()

    # 1. Cloudflare: cf-mitigated: challenge header OR (status in (403, 503) AND challenge indicators)
    cf_mitigated = hdrs.get("cf-mitigated", "").strip().lower()
    if cf_mitigated == "challenge":
        return True, "Cloudflare"
    if status in (403, 503) and (
        "just a moment..." in title_low
        or "attention required!" in title_low
        or "challenges.cloudflare.com" in text
        or "_cf_chl_opt" in text
        or "cdn-cgi/challenge-platform" in text
    ):
        return True, "Cloudflare"

    # 2. Sucuri
    if "Sucuri WebsiteFirewall" in text or "sucuri_cloudproxy_uuid" in text:
        return True, "Sucuri"

    # 3. Akamai / Imperva / DataDome known challenge titles & markers
    if status in (401, 403, 429, 503):
        if "pardon our interruption" in title_low or "_incapsula_resource" in text.lower():
            return True, "Imperva"
        if "datadome" in title_low or "geo.captcha-delivery.com" in text.lower():
            return True, "DataDome"
        if "access denied" in title_low and ("edgesuite.net" in text.lower() or "reference #" in text.lower()):
            return True, "Akamai"

    return False, ""
