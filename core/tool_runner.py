"""Adapter layer for optional external tools.

Every tool is optional. A missing binary, a non-zero exit or a timeout is a
skip, never a crash. Output is parsed into Finding objects.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from core.finding import CONFIRMED, HIGH_CONF, INFO, LOW, LOW_CONF, MEDIUM, MED_CONF, NEEDS_MANUAL, Finding
from core.logger import get
from paths import tmpdir

log = get("tsmss.tools")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
WAF_DETECTED_RE = re.compile(r"^\[\+\].*behind.*WAF", re.I)
WAF_NONE_RE = re.compile(r"^\[-\].*No WAF", re.I)
ARJUN_PARAM_RE = re.compile(r"^\[\+\].*[A-Za-z0-9_-]+$")


def strip_ansi(text: str) -> str:
    """Strip all ANSI escape sequences from *text* (H1)."""
    return ANSI_RE.sub("", text or "")


def parse_wafw00f_output(
    text: str,
    target_url: str = "https://example.com/",
    topology: str = "",
) -> list[Finding]:
    """Parse wafw00f stdout into at most 1 clean Finding with 0 ANSI escape bytes (H2, L4)."""
    clean = strip_ansi(text)
    if topology == "CF_DNS_ONLY":
        return [
            Finding(
                target=target_url,
                url=target_url,
                category="Infrastructure",
                module="external_tools",
                title="Cloudflare DNS only - no WAF in path",
                severity=INFO,
                confidence=HIGH_CONF,
                description="Domain uses Cloudflare nameservers without proxy protection; no Cloudflare WAF is in the request path.",
                evidence="Topology: CF_DNS_ONLY (Cloudflare DNS only - no WAF in path)",
                detection_method="wafw00f + DNS topology cross-check",
                remediation="Enable Cloudflare orange-cloud proxying or deploy an origin WAF.",
                tags=["external", "wafw00f", "waf"],
            )
        ]

    detected_lines: list[str] = []
    no_waf_lines: list[str] = []
    for raw_line in clean.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if WAF_DETECTED_RE.match(line):
            detected_lines.append(line)
        elif WAF_NONE_RE.match(line):
            no_waf_lines.append(line)

    if detected_lines:
        hit = detected_lines[0]
        return [
            Finding(
                target=target_url,
                url=target_url,
                category="Infrastructure",
                module="external_tools",
                title=f"WAF detected: {hit}",
                severity=INFO,
                confidence=HIGH_CONF,
                description="A Web Application Firewall was identified in front of the target.",
                evidence=hit,
                detection_method="wafw00f",
                remediation="Verify origin IP is not directly reachable bypassing the WAF.",
                tags=["external", "wafw00f", "waf"],
            )
        ]
    if no_waf_lines:
        hit = no_waf_lines[0]
        return [
            Finding(
                target=target_url,
                url=target_url,
                category="Infrastructure",
                module="external_tools",
                title="no WAF",
                severity=INFO,
                confidence=HIGH_CONF,
                description="No Web Application Firewall was detected by wafw00f.",
                evidence=hit,
                detection_method="wafw00f",
                remediation="Consider deploying a WAF or CDN edge protection.",
                tags=["external", "wafw00f", "waf"],
            )
        ]
    return []


def parse_arjun_output(text: str, target_url: str = "https://example.com/") -> list[Finding]:
    """Parse arjun stdout, dropping any Progress lines and keeping only valid parameter hits (H3)."""
    clean = strip_ansi(text)
    out: list[Finding] = []
    for raw_line in clean.splitlines():
        line = raw_line.strip()
        if not line or "progress" in line.lower():
            continue
        if ARJUN_PARAM_RE.match(line):
            out.append(
                Finding(
                    target=target_url,
                    url=target_url,
                    category="Discovery",
                    module="external_tools",
                    title=f"Parameter discovered (arjun): {line}",
                    severity=INFO,
                    confidence=MED_CONF,
                    description="Hidden or undocumented HTTP parameter discovered via arjun.",
                    evidence=line,
                    detection_method="arjun",
                    remediation="Validate and authorize all accepted input parameters.",
                    tags=["external", "arjun", "parameter"],
                )
            )
    return out


def parse_ffuf_output(
    text: str,
    target_url: str = "https://example.com/",
    seen_paths: set[str] | None = None,
) -> list[Finding]:
    """Parse ffuf JSON `results[]` into 1 finding per entry titled `<path> [<status>]`, dropping commandline/tmp paths and deduping against `seen_paths` (H4)."""
    clean = strip_ansi(text).strip()
    if not clean:
        return []
    seen = seen_paths if seen_paths is not None else set()
    entries: list[dict] = []
    try:
        data = json.loads(clean)
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            entries = [r for r in data["results"] if isinstance(r, dict)]
        elif isinstance(data, list):
            entries = [r for r in data if isinstance(r, dict)]
    except ValueError:
        for line in clean.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    if isinstance(obj.get("results"), list):
                        entries.extend(r for r in obj["results"] if isinstance(r, dict))
                    else:
                        entries.append(obj)
            except ValueError:
                continue

    out: list[Finding] = []
    for item in entries:
        url = str(item.get("url") or target_url)
        status = int(item.get("status") or 0)
        length = int(item.get("length") or 0)
        words = int(item.get("words") or 0)
        fuzz_inp = ""
        if isinstance(item.get("input"), dict):
            fuzz_inp = str(item["input"].get("FUZZ") or "")
        path = urlsplit(url).path or (f"/{fuzz_inp.lstrip('/')}" if fuzz_inp else "/")
        norm_path = "/" + path.lstrip("/")
        if norm_path in seen:
            continue
        seen.add(norm_path)
        title = f"{norm_path} [{status}]"
        ev_obj = {"url": url, "status": status, "length": length, "words": words}
        out.append(
            Finding(
                target=target_url,
                url=url,
                endpoint=norm_path,
                category="Discovery",
                module="external_tools",
                title=title,
                severity=LOW if status in (200, 204, 401, 403) else INFO,
                confidence=MED_CONF,
                description=f"Content discovery identified {norm_path} returning HTTP {status}.",
                evidence=json.dumps(ev_obj),
                detection_method="ffuf",
                remediation="Verify whether this endpoint is intended to be publicly accessible.",
                tags=["external", "ffuf", "discovery"],
            )
        )
    return out

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
    only_query: bool = False

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
    def __init__(self, config, target, evidence, ctx=None):
        self.config = config
        self.target = target
        self.evidence = evidence
        self.ctx = ctx
        self.rate = int(config.get("tools.rate_limit", 5))
        self.max_runtime = int(config.get("tools.max_runtime", 180))
        self.allow = set(config.get("tools.enabled", []) or [])
        self.deny = set(config.get("tools.disabled", []) or [])
        self.home = tmpdir(prefix="tsmss-tool-")

    def select(self) -> list[ToolSpec]:
        out = []
        for spec in load_registry():
            if self.allow and spec.id not in self.allow:
                continue
            if spec.id in self.deny:
                continue
            if spec.only_query and "?" not in self.target.url:
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
        clean = strip_ansi(text)
        if not clean.strip():
            return []
        if spec.id == "wafw00f":
            topo = getattr(self.ctx, "topology", "") if self.ctx else ""
            return parse_wafw00f_output(clean, self.target.url, topology=topo)
        if spec.id == "arjun":
            return parse_arjun_output(clean, self.target.url)
        if spec.id == "ffuf":
            seen = getattr(self.ctx, "seen_paths", None) if self.ctx else None
            return parse_ffuf_output(clean, self.target.url, seen_paths=seen)

        rows = []
        if spec.output in ("jsonl", "json"):
            for line in clean.splitlines():
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
            rows = [{"line": l.strip()} for l in clean.splitlines() if l.strip()]
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
