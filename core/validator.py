"""Target normalization, dedupe, and pre-flight validation."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_BAD_SCHEME = re.compile(r"^(ftp|file|javascript|data):", re.I)
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})*\.?$")


@dataclass
class ValidationResult:
    url: str
    valid: bool
    reason: str = ""
    normalized: str = ""


def normalize(raw: str) -> str:
    s = (raw or "").strip()
    if not s or s.startswith("#"):
        return ""
    if "#" in s:
        s = s.split("#", 1)[0].strip()
        if not s:
            return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "https://" + s.lstrip("/")
    parts = urlsplit(s)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return s
    port = parts.port
    netloc = host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def validate(raw: str) -> ValidationResult:
    if not (raw or "").strip():
        return ValidationResult(raw, False, "empty line")
    if (raw or "").strip().startswith("#"):
        return ValidationResult(raw, False, "comment")
    if _BAD_SCHEME.match((raw or "").strip()):
        return ValidationResult(raw, False, "unsupported scheme")
    try:
        norm = normalize(raw)
        parts = urlsplit(norm)
    except ValueError as exc:
        return ValidationResult(raw, False, f"unparsable: {exc}")
    if parts.scheme not in ("http", "https"):
        return ValidationResult(raw, False, f"scheme '{parts.scheme}'")
    host = parts.hostname or ""
    if not host:
        return ValidationResult(raw, False, "missing host")
    if " " in host:
        return ValidationResult(raw, False, "space in host")
    if not _HOST_RE.match(host) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return ValidationResult(raw, False, f"invalid hostname '{host}'")
    if len(norm) > 2048:
        return ValidationResult(raw, False, "url too long")
    return ValidationResult(raw, True, "", norm)


def load_targets(path) -> tuple[list[str], list[dict]]:
    """Return (unique normalized valid targets, rejection log)."""
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"target file not found: {path}")
    accepted: list[str] = []
    seen: set[str] = set()
    rejected: list[dict] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        res = validate(line)
        if not res.valid:
            if res.reason not in ("comment", "empty line"):
                rejected.append({"line": lineno, "raw": line.strip(), "reason": res.reason})
            continue
        key = res.normalized.lower()
        if key in seen:
            rejected.append({"line": lineno, "raw": line.strip(), "reason": "duplicate"})
            continue
        seen.add(key)
        accepted.append(res.normalized)
    return accepted, rejected