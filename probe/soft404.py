"""Per-host Soft-404 calibration, SPA fingerprinting, and content-signature gate (Work Item B)."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import secrets

from core.finding import CRITICAL, HIGH, INFO, LOW, MEDIUM

_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>[\s\S]*?</\1\s*>", re.I)
_WS_RE = re.compile(r"\s+")

SPA_FINGERPRINTS: dict[str, re.Pattern[str]] = {
    "data-capo": re.compile(r"\bdata-capo\b", re.I),
    "__next_f": re.compile(r"\b__next_f\b"),
    "__NUXT__": re.compile(r"\b__NUXT__\b"),
    'id="app"': re.compile(r'\bid\s*=\s*["\']app["\']', re.I),
    'id="root"': re.compile(r'\bid\s*=\s*["\']root["\']', re.I),
}

# B4: Content-signature gate — HTTP 200 alone is never sufficient.
CONTENT_SIGNATURES: dict[str, re.Pattern[str]] = {
    "/.env": re.compile(r"(?m)^[A-Z_][A-Z0-9_]*\s*="),
    "/.env.local": re.compile(r"(?m)^[A-Z_][A-Z0-9_]*\s*="),
    "/wp-config.php.bak": re.compile(r"<\?php"),
    "/config.php.bak": re.compile(r"<\?php"),
    "/swagger-ui.html": re.compile(r"(?i)(swagger-ui|openapi|SwaggerUIBundle)"),
    "/swagger.json": re.compile(r'(?i)("(?:swagger|openapi)"\s*:\s*"[23]\.)'),
    "/openapi.json": re.compile(r'(?i)("(?:swagger|openapi)"\s*:\s*"[23]\.)'),
    "/api/swagger.json": re.compile(r'(?i)("(?:swagger|openapi)"\s*:\s*"[23]\.)'),
    "/v2/api-docs": re.compile(r'(?i)("(?:swagger|openapi)"\s*:\s*"[23]\.)'),
    "/api-docs": re.compile(r'(?i)(swagger-ui|"(?:swagger|openapi)"\s*:|"paths"\s*:)'),
    "/swagger/": re.compile(r"(?i)(swagger-ui|SwaggerUIBundle|openapi)"),
    "/docs": re.compile(r"(?i)(swagger-ui|openapi|redoc)"),
    "/redoc": re.compile(r"(?i)(redoc|openapi|spec-url)"),
    "/graphql": re.compile(r'(?i)("__schema"|"data"\s*:|"errors"\s*:|GraphiQL|Apollo)'),
    "/api/graphql": re.compile(r'(?i)("__schema"|"data"\s*:|"errors"\s*:|GraphiQL|Apollo)'),
    "/.git/config": re.compile(r"(?m)^\[core\]"),
    "/.git/HEAD": re.compile(r"(?m)^(ref:\s+refs/heads/|[0-9a-f]{40}\s*$)"),
    "/backup.zip": re.compile(r"^PK\x03\x04"),
    "/backup.sql": re.compile(r"(?i)(CREATE\s+TABLE|INSERT\s+INTO|--\s*MySQL\s+dump)"),
    "/phpinfo.php": re.compile(r"PHP Version|phpinfo\(\)"),
    "/server-status": re.compile(r"Apache Server Status|requests currently being processed"),
    "/.htaccess": re.compile(r"(?m)^(RewriteEngine|AddType|Options|Deny\s+from|Require\s+)"),
    "/composer.json": re.compile(r'"require"\s*:\s*\{'),
    "/package.json": re.compile(r'"(?:dependencies|devDependencies)"\s*:\s*\{'),
    "/Dockerfile": re.compile(r"(?m)^FROM\s+\S+"),
    "/.DS_Store": re.compile(r"Bud1"),
    "/admin": re.compile(r"(?i)(<form\b[^>]*password|admin\s*(?:dashboard|panel|console|login)|wp-login)"),
}

_DOWNGRADE_MAP = {
    CRITICAL: HIGH,
    HIGH: MEDIUM,
    MEDIUM: LOW,
    LOW: INFO,
    INFO: INFO,
}


@dataclass
class BaselineSample:
    path: str
    status: int
    length: int
    md5: str


@dataclass
class Soft404Baseline:
    samples: list[BaselineSample] = field(default_factory=list)
    calibration: str = "stable"  # "stable" | "unstable" | "disabled"
    is_spa: bool = False
    spa_markers: list[str] = field(default_factory=list)

    @property
    def unstable(self) -> bool:
        return self.calibration == "unstable"


def normalize_body(body: str) -> str:
    """Strip <script>/<style> blocks, collapse whitespace, and lowercase (B1)."""
    if not body:
        return ""
    stripped = _SCRIPT_STYLE_RE.sub(" ", body)
    return _WS_RE.sub(" ", stripped).strip().lower()


def body_md5(body: str) -> str:
    """Compute MD5 hex digest of the normalized body (B1)."""
    norm = normalize_body(body)
    return hashlib.md5(norm.encode("utf-8", "replace")).hexdigest()


def detect_spa_markers(body: str) -> list[str]:
    """Return matched SPA framework fingerprints present in *body* (B6)."""
    if not body:
        return []
    return [name for name, pat in SPA_FINGERPRINTS.items() if pat.search(body)]


def downgrade_one_level(severity: str) -> str:
    """Downgrade severity by one level when soft-404 calibration is unstable (B5)."""
    return _DOWNGRADE_MAP.get((severity or INFO).upper(), INFO)


def matches_content_signature(path: str, body: str) -> bool:
    """Return True only if *body* matches the expected content regex for *path* (B4)."""
    if not body:
        return False
    sig = CONTENT_SIGNATURES.get(path)
    if sig is None:
        for key, pat in CONTENT_SIGNATURES.items():
            if path.endswith(key):
                sig = pat
                break
    if sig is None:
        return False
    return bool(sig.search(body[:12000]))


def is_soft404(status: int, body: str, baseline: Soft404Baseline | None) -> bool:
    """Classify response as soft-404 per B2:
    - md5 of normalized body matches any baseline sample, OR
    - status matches a baseline sample AND abs(len - baseline_len) < max(80, 1% baseline_len).
    """
    if baseline is None or baseline.calibration == "disabled" or not baseline.samples:
        return False
    cur_md5 = body_md5(body)
    cur_len = len(body or "")
    for sample in baseline.samples:
        if sample.status == 0:
            continue
        if cur_md5 == sample.md5 and sample.length > 0:
            return True
        threshold = max(80, int(0.01 * sample.length))
        if status == sample.status and abs(cur_len - sample.length) < threshold:
            return True
    return False


async def calibrate_soft404(ctx) -> Soft404Baseline:
    """Perform 3 random 8-char path probes on the target host and cache on ctx (B1, B5, B6)."""
    cached = getattr(ctx, "soft404", None)
    if cached is not None:
        return cached

    if bool(ctx.config.get("scan.no_soft404", False)):
        disabled_bl = Soft404Baseline(calibration="disabled")
        ctx.soft404 = disabled_bl
        ctx.soft404_calibration = "disabled"
        return disabled_bl

    base_url = str(ctx.target.root).rstrip("/")
    samples: list[BaselineSample] = []
    spa_hits: set[str] = set()

    home = getattr(ctx, "homepage", None)
    if home is not None and getattr(home, "body", ""):
        spa_hits.update(detect_spa_markers(home.body))

    for _ in range(3):
        rand_slug = secrets.token_hex(4)  # 8-char random hex path
        probe_path = f"/{rand_slug}"
        url = f"{base_url}{probe_path}"
        resp = await ctx.http.request("GET", url, retry=False)
        b_text = resp.body if (resp and resp.ok) else ""
        st = resp.status if resp else 0
        samples.append(
            BaselineSample(
                path=probe_path,
                status=st,
                length=len(b_text),
                md5=body_md5(b_text),
            )
        )
        if b_text:
            spa_hits.update(detect_spa_markers(b_text))

    lengths = [s.length for s in samples if s.status > 0]
    calibration = "stable"
    if len(lengths) >= 2:
        max_l, min_l = max(lengths), min(lengths)
        if max_l > 0 and (max_l - min_l) / max_l > 0.25:
            calibration = "unstable"

    baseline = Soft404Baseline(
        samples=samples,
        calibration=calibration,
        is_spa=bool(spa_hits),
        spa_markers=sorted(spa_hits),
    )
    ctx.soft404 = baseline
    ctx.soft404_calibration = calibration
    return baseline


def evaluate_path_probe(
    path: str,
    status: int,
    body: str,
    default_severity: str,
    baseline: Soft404Baseline | None,
    no_soft404: bool = False,
) -> tuple[bool, str, str]:
    """Evaluate a probed path response under B2, B3, B4, B5, B6.

    Returns ``(is_real_or_soft404_reportable, effective_severity, reason_tag)``:
    - If status != 200 or empty body: ``(False, INFO, "non-200")``
    - If soft-404 matched (and not --no-soft404): ``(True, INFO, "soft-404")``
    - If SPA host and B4 content signature does NOT match: ``(True, INFO, "soft-404 (SPA catch-all)")``
    - If B4 content signature matches: ``(True, severity (downgraded 1 level if unstable), "verified")``
    - If B4 content signature fails on non-soft-404 host: ``(False, INFO, "signature-mismatch")``
    """
    if status != 200 or not body or len(body) < 4:
        return False, INFO, "non-200"

    sig_ok = matches_content_signature(path, body)
    soft_hit = (not no_soft404) and is_soft404(status, body, baseline)
    is_spa = bool(baseline and baseline.is_spa) or bool(detect_spa_markers(body))

    if soft_hit and not sig_ok:
        return True, INFO, "soft-404"

    if is_spa and not sig_ok:
        if no_soft404:
            return False, INFO, "signature-mismatch"
        return True, INFO, "soft-404 (SPA catch-all)"

    if not sig_ok:
        return False, INFO, "signature-mismatch"

    sev = default_severity
    if baseline and baseline.unstable and not no_soft404:
        sev = downgrade_one_level(sev)
        return True, sev, "verified (soft404_calibration=unstable)"
    return True, sev, "verified"
