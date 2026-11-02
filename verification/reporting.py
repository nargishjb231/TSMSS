"""Phase 5: Output Generation — JSON Schema Enrichment & Chunked Markdown Reporting.

JSON Finding Schema:
  `id, host, path, param, class, context, severity, confidence, cwe, cvss, oracle,
   request, response_hash, artifacts[], first_seen, last_seen, edge, csp_source, check_outcome`

Markdown per target + index:
  Split at 100k chars.
  Header banner lists every CRITICAL/HIGH with host.
  Per-target "Verification" section separating MACHINE-CONFIRMED from NEEDS_MANUAL.
"""
from __future__ import annotations

import datetime
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.finding import CRITICAL, HIGH, INFO, LOW, MEDIUM, Finding
from core.report_manager import split_markdown_chunks
from verification.doctrine import CANDIDATE, CONFIRMED, LIKELY

logger = logging.getLogger("tsmss.verification.reporting")


@dataclass
class VerifiedFindingJSON:
    id: str
    host: str
    path: str
    param: str
    finding_class: str
    context: str
    severity: str
    confidence: str
    cwe: str
    cvss: float
    oracle: str
    request: str
    response_hash: str
    artifacts: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    edge: bool = False
    csp_source: str = "header"
    check_outcome: str = "PASS"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Rename finding_class to class in JSON output
        d["class"] = d.pop("finding_class")
        return d


def format_verified_json_findings(
    findings: list[Finding | dict[str, Any]],
    scan_id: str = "default_scan",
) -> list[dict[str, Any]]:
    """Convert findings to enriched Phase 5 JSON schema."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    out: list[dict[str, Any]] = []

    for f in findings:
        if isinstance(f, Finding):
            target_url = f.url or f.target or ""
            parsed = urlparse(target_url)
            host = parsed.netloc or target_url
            path = parsed.path or "/"

            # Map category/module to class
            f_class = f.category or f.module or "Vulnerability"
            context = f.details.get("context", "UNKNOWN") if hasattr(f, "details") and isinstance(f.details, dict) else "UNKNOWN"
            oracle = f.details.get("oracle", f.detection_method or "") if hasattr(f, "details") and isinstance(f.details, dict) else (f.detection_method or "")
            req = f.details.get("request", "") if hasattr(f, "details") and isinstance(f.details, dict) else ""
            resp_hash = f.details.get("response_hash", "") if hasattr(f, "details") and isinstance(f.details, dict) else ""
            arts = f.details.get("artifacts", []) if hasattr(f, "details") and isinstance(f.details, dict) else []
            edge = bool(f.details.get("edge", False)) if hasattr(f, "details") and isinstance(f.details, dict) else False
            csp_src = f.details.get("csp_source", "header") if hasattr(f, "details") and isinstance(f.details, dict) else "header"

            cvss_score = 0.0
            if f.severity == CRITICAL:
                cvss_score = 9.5
            elif f.severity == HIGH:
                cvss_score = 8.0
            elif f.severity == MEDIUM:
                cvss_score = 5.5
            elif f.severity == LOW:
                cvss_score = 3.0

            fid = getattr(f, "finding_id", getattr(f, "id", "TSMSS-00000"))
            param_name = getattr(f, "parameter", getattr(f, "param", "")) or ""

            vj = VerifiedFindingJSON(
                id=fid,
                host=host,
                path=path,
                param=param_name,
                finding_class=f_class,
                context=context,
                severity=f.severity,
                confidence=f.confidence,
                cwe=f.cwe or "",
                cvss=cvss_score,
                oracle=oracle,
                request=req,
                response_hash=resp_hash,
                artifacts=arts,
                first_seen=f.first_seen or now_iso,
                last_seen=f.last_seen or now_iso,
                edge=edge,
                csp_source=csp_src,
                check_outcome="CONFIRMED" if f.confidence == CONFIRMED else "NEEDS_MANUAL",
            )
            out.append(vj.to_dict())
        elif isinstance(f, dict):
            # Already a dict
            out.append(f)

    return out


def generate_verified_markdown_report(
    target_results: dict[str, list[Finding]],
    scan_id: str,
    output_dir: Path,
    proof_md_path: Path | None = None,
) -> list[Path]:
    """Generate Phase 5 Markdown reports split at 100k chars."""
    output_dir.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        f"# TSMSS Verification-First Security Audit Report",
        f"**Scan ID:** `{scan_id}`  ",
        f"**Generated:** `{datetime.datetime.now(datetime.timezone.utc).isoformat()}`\n",
    ]

    # Header banner lists every CRITICAL/HIGH with host
    high_crit_list: list[tuple[str, str, str, str]] = []
    for host, f_list in target_results.items():
        for f in f_list:
            if f.severity in (CRITICAL, HIGH):
                high_crit_list.append((host, f.severity, f.title, f.confidence))

    if high_crit_list:
        lines.append("> [!WARNING]")
        lines.append("> **CRITICAL & HIGH VULNERABILITY ALERT BANNER**")
        for h, sev, title, conf in high_crit_list:
            lines.append(f"> - `[{sev}]` **{h}** — {title} (Confidence: `{conf}`)")
        lines.append("")
    else:
        lines.append("> [!NOTE]\n> No CRITICAL or HIGH severity findings detected.\n")

    if proof_md_path and proof_md_path.exists():
        lines.append(f"[**View Proof Manifest (proof.md)**](file:///{str(proof_md_path).replace('\\', '/')})\n")

    # Per-target "Verification" section separating MACHINE-CONFIRMED from NEEDS_MANUAL
    for target_url, f_list in target_results.items():
        lines.append(f"## Target: `{target_url}`\n")

        confirmed_findings = [f for f in f_list if f.confidence == CONFIRMED]
        manual_findings = [f for f in f_list if f.confidence != CONFIRMED]

        lines.append("### Section 1: MACHINE-CONFIRMED (All 5 Gates Passed)\n")
        if confirmed_findings:
            lines.append("| ID | Severity | CWE | Title | Oracle |")
            lines.append("|---|---|---|---|---|")
            for f in confirmed_findings:
                fid = getattr(f, "finding_id", getattr(f, "id", "TSMSS-00000"))
                oracle_desc = f.detection_method or "Automated oracle test"
                lines.append(f"| `{fid}` | **{f.severity}** | `{f.cwe}` | {f.title} | {oracle_desc} |")
        else:
            lines.append("_No machine-confirmed findings for this target._\n")

        lines.append("\n### Section 2: NEEDS MANUAL VERIFICATION (Candidate / Incomplete Gates)\n")
        if manual_findings:
            lines.append("| ID | Severity | Confidence | Title | Reason / Note |")
            lines.append("|---|---|---|---|---|")
            for f in manual_findings:
                fid = getattr(f, "finding_id", getattr(f, "id", "TSMSS-00000"))
                note = f.evidence or "Requires manual inspection"
                lines.append(f"| `{fid}` | {f.severity} | `{f.confidence}` | {f.title} | {note[:60]} |")
        else:
            lines.append("_No manual candidates._\n")

        lines.append("\n---\n")

    full_markdown = "\n".join(lines) + "\n"
    prefix = f"report_verify_{scan_id}"
    chunks = split_markdown_chunks(full_markdown, max_chars=100_000)
    written_files: list[Path] = []
    if len(chunks) == 1:
        out_file = output_dir / f"{prefix}.md"
        out_file.write_text(chunks[0], encoding="utf-8")
        written_files.append(out_file)
    else:
        index_lines = [
            f"# {prefix} Index",
            f"Audit report split into {len(chunks)} chunks:",
        ]
        for idx, chunk in enumerate(chunks, 1):
            chunk_file = output_dir / f"{prefix}_{idx}.md"
            chunk_file.write_text(chunk, encoding="utf-8")
            written_files.append(chunk_file)
            index_lines.append(f"- [{chunk_file.name}](./{chunk_file.name})")
        index_file = output_dir / f"{prefix}_index.md"
        index_file.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
        written_files.insert(0, index_file)
    return written_files
