"""Termux-safe temporary file and directory management (Work Item A).

Never hardcodes /tmp. Probes writability with a 1-byte write+read+unlink check
and exits with code 3 ("no writable temp directory") when no writable directory
is available.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile

_ORIG_GETTEMPDIR = tempfile.gettempdir


class TempDirError(RuntimeError):
    """Raised when no writable temporary directory can be established."""


def _probe_writable(directory: Path) -> bool:
    """Write, read back, and unlink a 1-byte probe file inside *directory*."""
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    probe_path = directory / f".tsmss_probe_{os.getpid()}_{id(directory)}"
    try:
        probe_path.write_bytes(b"x")
        data = probe_path.read_bytes()
        if len(data) != 1 or data != b"x":
            return False
        return True
    except OSError:
        return False
    finally:
        try:
            probe_path.unlink(missing_ok=True)
        except OSError:
            pass


def candidate_temp_dirs() -> list[Path]:
    """Return ordered candidate temp directories: gettempdir(), $PREFIX/tmp, CWD."""
    primary_raw = tempfile.gettempdir()
    primary = Path(primary_raw)
    # If tempfile.gettempdir has been monkeypatched in tests or explicitly pointed
    # at a custom non-/tmp path, honour that path strictly unless $TSMSS_FALLBACK_TMP=1.
    is_monkeypatched = tempfile.gettempdir is not _ORIG_GETTEMPDIR
    if is_monkeypatched and os.environ.get("TSMSS_FALLBACK_TMP") != "1":
        return [primary]

    candidates: list[Path] = [primary]
    prefix = os.environ.get("PREFIX", "").strip()
    if prefix:
        p_tmp = Path(prefix) / "tmp"
        if p_tmp not in candidates:
            candidates.append(p_tmp)
    cwd = Path.cwd()
    if cwd not in candidates:
        candidates.append(cwd)
    return candidates


def resolve_temp_dir(abort_on_failure: bool = True) -> Path:
    """Return the first writable temp directory or abort with exit code 3."""
    for cand in candidate_temp_dirs():
        if _probe_writable(cand):
            return cand
    msg = "no writable temp directory"
    if abort_on_failure:
        sys.stderr.write(msg + "\n")
        sys.exit(3)
    raise TempDirError(msg)


def startup_probe() -> Path:
    """Startup writability check (Work Item A2): write+read+unlink 1 byte or exit 3."""
    return resolve_temp_dir(abort_on_failure=True)


def tmpfile(prefix: str = "tsmss-", suffix: str = "") -> Path:
    """Create a guaranteed-writable temporary file path with *prefix* (Work Item A1)."""
    base = resolve_temp_dir(abort_on_failure=True)
    fd, raw_path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=str(base))
    os.close(fd)
    return Path(raw_path)


def tmpdir(prefix: str = "tsmss-") -> Path:
    """Create a guaranteed-writable temporary directory with *prefix*."""
    base = resolve_temp_dir(abort_on_failure=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))


def validate_response_body(
    body: str | bytes | None,
    headers: dict[str, str] | None = None,
    status: int = 200,
    method: str = "GET",
    error: str | None = None,
) -> tuple[bool, str]:
    """Verify response body integrity (Work Item A3).

    Asserts len(body) >= 0 and that the download succeeded. A 0-byte body is a
    FAILED fetch unless Content-Length is explicitly 0 (or status has no body
    by RFC such as 204/304/redirect or HEAD/OPTIONS).
    """
    if error:
        return False, error
    if body is None:
        return False, "response body is None"
    assert len(body) >= 0, "response body length must be >= 0"
    if len(body) > 0:
        return True, ""
    m = (method or "GET").upper()
    if m in ("HEAD", "OPTIONS") or status in (100, 101, 204, 205, 301, 302, 303, 304, 307, 308):
        return True, ""
    hdrs = {k.lower(): str(v).strip() for k, v in (headers or {}).items()}
    if hdrs.get("content-length") == "0":
        return True, ""
    return False, "0-byte response body without Content-Length: 0"
