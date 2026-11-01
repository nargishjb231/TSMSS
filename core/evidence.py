"""Evidence capture: bounded, deduplicated, disk-backed."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

_SECRET_HINTS = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|authorization|bearer)\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{8,})")


class EvidenceStore:
    def __init__(self, directory: Path, max_bytes: int = 8192):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self._seen: set[str] = set()

    def _key(self, label: str, body: str) -> str:
        return hashlib.sha1(f"{label}|{body}".encode("utf-8", "replace")).hexdigest()[:16]

    def save(self, label: str, body: str, kind: str = "txt") -> str:
        """Persist truncated evidence, return a repo-relative path or inline snippet."""
        body = body or ""
        if len(body) > self.max_bytes:
            body = body[: self.max_bytes] + "\n...[truncated]"
        key = self._key(label, body)
        if key in self._seen:
            return f"evidence/{key}.{kind}"
        self._seen.add(key)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:60]
        path = self.dir / f"{safe}_{key}.{kind}"
        try:
            path.write_text(body, encoding="utf-8", errors="replace")
        except OSError:
            return body[:600]
        return f"evidence/{path.name}"

    @staticmethod
    def excerpt(body: str, needle: str = "", radius: int = 120) -> str:
        body = (body or "").replace("\n", " ")
        if needle:
            idx = body.find(needle)
            if idx >= 0:
                start = max(0, idx - radius)
                return ("..." if start else "") + body[start: idx + len(needle) + radius] + "..."
        return body[: 2 * radius]

    @staticmethod
    def redact(body: str) -> str:
        return _SECRET_HINTS.sub(lambda m: f"{m.group(1)}={m.group(2)[:6]}***", body or "")