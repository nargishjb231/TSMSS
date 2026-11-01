"""Adapter layer for optional external tools.

Every tool is optional. A missing binary, a non-zero exit or a timeout is a
skip, never a crash. Output is parsed into Finding objects.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from core.finding import CONFIRMED, HIGH_CONF, LOW_CONF, MEDIUM, MED_CONF, NEEDS_MANUAL
from core.logger import get

log = get("tsmss.tools")

REGISTRY = Path(__file__).resolve().parent.parent / "config" / "tools.yaml"
WORDS = Path(__file__).resolve().parent.parent / "config" / "wordlist.txt"

_CONF_MAP = {
    "CONFIRMED": CONFIRMED, "HIGH CONFIDENCE": HIGH_CONF,
    "MEDIUM CONFIDENCE": MED_CONF, "LOW CONFIDENCE": LOW_CONF,
}


@dataclass
class ToolSpec:
    id: str
    bin: str
    category: str
    install: str
    pkg: str
    output: str
    args: list[str]
    timeout: int = 90
    confidence: str = NEEDS_MANUAL
    map: dict | None = None
    line_title: str = ""
    line_severity: str = "INFO"
    needs_root: bool = False
    needs_wordlist: bool = False
    needs_dir: bool = False

    @property
    def conf(self) -> str:
        return _CONF_MAP.get(self.confidence, NEEDS_MANUAL)


def load_registry() -> list[ToolSpec]:
    if not REGISTRY.exists():
        return []
    try:
        raw = yaml.safe_load(REGISTRY.read_text(encoding="utf-8")) or []
    except (yaml.YAMLError, OSError) as exc:
        log.warning("tools.yaml unreadable: %s", exc)
        return []
    specs = []
    for item in raw:
        try:
            specs.append(ToolSpec(**item))
        except TypeError as exc:
            log.warning("bad tool entry %s: %s", item.get("id"), exc)
    return specs


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def usable(spec: ToolSpec, config) -> tuple[bool, str]:
    if shutil.which(spec.bin) is None:
        return False, "not installed"
    if spec.needs_root and not (config.get("tools.allow_root_tools", False) or is_root()):
        return False, "needs root"
    if spec.needs_wordlist and not WORDS.exists():
        return False, "wordlist missing"
    return True, "ready"


def _dig(obj: dict, path: str):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(part)
        if cur is None:
            return ""
    if isinstance(cur, list):
        return ", ".join(str(x) for x in cur)
    return cur


class ToolRunner:
    def __init__(self, config, target, evidence):
        self.config = config
        self.target = target
        self.evidence = evidence
        self.rate = int(config.get("tools.rate_limit", 5))
        self.max_runtime = int(config.get("tools.max_runtime", 180))
        self.allow = set(config.get("tools.enabled", []) or [])
        self.deny = set(config.get("tools.disabled", []) or [])
        self.home = Path(tempfile.mkdtemp(prefix="tsmss-tool-"))

    def select(self) -> list[ToolSpec]:
        out = []
        for spec in load_registry():
            if self.allow and spec.id not in self.allow:
                continue
            if spec.id in self.deny:
                continue
            ok, reason = usable(spec, self.config)
            if not ok:
                log.info("tool %s skipped: %s", spec.id, reason)
                continue
            out.append(spec)
        return out

    def _argv(self, spec: ToolSpec, outfile: Path, workdir: Path) -> list[str]:
        values = {
            "target": self.target.url,
            "host": self.target.host,
            "root": self.target.root.rstrip("/"),
            "rate": str(self.rate),
            "outfile": str(outfile),
            "dir": str(workdir),
            "wordlist": str(WORDS),
        }
        return [spec.bin] + [a.format(**values) for a in spec.args]

    async def run(self, spec: ToolSpec) -> list:
        outfile = self.home / f"{spec.id}.json"
        workdir = self.home / f"{spec.id}-dir"
        if spec.needs_dir:
            workdir.mkdir(parents=True, exist_ok=True)
        argv = self._argv(spec, outfile, workdir)
        timeout = min(spec.timeout, self.max_runtime)
        raw = ""
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, cwd=str(self.home))
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            raw = out.decode("utf-8", "replace")[:2_000_000]
        except asyncio.TimeoutError:
            log.info("tool %s timed out after %ss", spec.id, timeout)
        except OSError as exc:
            log.info("tool %s failed to start: %s", spec.id, exc)
            return []

        text = outfile.read_text(encoding="utf-8", errors="replace") if outfile.exists() else raw
        return self._parse(spec, text)

    def _parse(self, spec: ToolSpec, text: str) -> list:
        if not text.strip():
            return []
        rows = []
        if spec.output in ("jsonl", "json"):
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                for one in (obj if isinstance(obj, list) else [obj]):
                    if isinstance(one, dict):
                        rows.append(one)
        else:
            rows = [{"line": l.strip()} for l in text.splitlines() if l.strip()]
        return [f for f in (self._finding(spec, r) for r in rows[:80]) if f]

    def _finding(self, spec: ToolSpec, row: dict):
        from core.finding import Finding
        if spec.output == "lines":
            title = spec.line_title.format(line=row.get("line", "")[:160]) if spec.line_title \
                else f"{spec.id}: {row.get('line', '')[:160]}"
            severity, url, desc, fix, cwe = spec.line_severity, self.target.url, "", "", None
        else:
            m = spec.map or {}
            title = str(_dig(row, m.get("title", "")) or spec.id)[:180]
            sev = str(_dig(row, m.get("severity", "")) or "").upper()
            severity = sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else MEDIUM
            url = str(_dig(row, m.get("url", "")) or self.target.url)
            desc = str(_dig(row, m.get("description", "")) or "")
            fix = str(_dig(row, m.get("remediation", "")) or "")
            cwe_raw = str(_dig(row, m.get("cwe", "")) or "")
            cwe = cwe_raw if cwe_raw.upper().startswith("CWE-") else None
        if not title.strip():
            return None
        ev = json.dumps(row, ensure_ascii=False)[:1200] if spec.output != "lines" else title
        return Finding(
            target=self.target.url, category=spec.category, module="external_tools",
            title=title, severity=severity, confidence=spec.conf,
            description=desc or f"Reported by external tool '{spec.id}'. Verify before acting.",
            evidence=ev, detection_method=f"{spec.id} ({' '.join(spec.args)})",
            cwe=cwe, remediation=fix or f"Review the {spec.id} report for this target.",
            url=url, tags=["external", spec.id])

    def cleanup(self) -> None:
        shutil.rmtree(self.home, ignore_errors=True)
