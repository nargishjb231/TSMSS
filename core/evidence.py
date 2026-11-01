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
        # digest -> repo-relative path, so repeats return the identical string
        self._seen: dict[str, str] = {}
        # prefix returned by save(); must mirror the real folder name
        self._prefix = self.dir.name or "evidence"

    def _key(self, label: str, body: str) -> str:
        return hashlib.sha1(f"{label}|{body}".encode("utf-8", "replace")).hexdigest()[:16]

    def save(self, label: str, body: str, kind: str = "txt") -> str:
        """Persist truncated evidence.

        Returns a path relative to the store's parent directory, e.g.
        ``evidence/<label>_<digest>.txt``. The prefix is taken from this
        store's own directory name so the value stays correct whichever
        directory the caller mounts. Falls back to an inline snippet when
        the file cannot be written.
        """
        body = body or ""
        if len(body) > self.max_bytes:
            body = body[: self.max_bytes] + "\n...[truncated]"
        key = self._key(label, body)
        slot = f"{key}.{kind}"
        if slot in self._seen:
            return self._seen[slot]
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:60]
        path = self.dir / f"{safe}_{key}.{kind}"
        try:
            path.write_text(body, encoding="utf-8", errors="replace")
        except OSError:
            return body[:600]
        self._seen[slot] = f"{self._prefix}/{path.name}"
        return self._seen[slot]

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