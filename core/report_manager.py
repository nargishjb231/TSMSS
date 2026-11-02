"""Report rendering: HTML, Markdown, JSON (AI v2 + v1 compatible), JSONL, TXT, CSV, SARIF v2.1.0, AI Package & Diff."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import html
import io
import json
from pathlib import Path
import re
from string import Template
from typing import Any

from ai.packager import build_ai_upload_package
from config import SEVERITY_ORDER, SEVERITY_WEIGHTS
from core.finding import Finding, compute_global_score, score_breakdown, score_counts, severity_rank
from core.verification import map_confidence_to_verification

SCORE_METHOD = """Each severity contributes a saturating deduction
cap * n / (n + k): CRITICAL cap 90 k 3, HIGH cap 25 k 5, MEDIUM cap 12 k 8,
LOW cap 5 k 15, INFO 0. Score = max(0, 100 - total). Caps stop a noisy target
from flooring at 0 while repeats still cost less than first occurrences.
Grades: A>=90, B>=80, C>=65, D>=50, E>=30, F<30. A relative prioritisation
aid, not a compliance verdict; absence of findings is not proof of security."""

STANDARDS_VERSIONS = {
    "owasp_wstg": "v4.2",
    "owasp_top10": "2025",
    "owasp_api_top10": "2023",
    "owasp_asvs": "v4.0.3",
    "owasp_masvs": "v2.1.0",
}

LIMITATIONS = [
    "Non-destructive testing only; no unauthorized exploitation, credential attacks, "
    "account creation, or write operations.",
    "Single-entry-point crawl. Deep paths, SPA routes and authenticated areas are under-sampled.",
    "Vulnerability classes that need state (IDOR/BOLA, SSRF, file upload, business logic) are "
    "flagged as indicators and require manual confirmation with authorized test accounts.",
    "CDN/WAF edges may mask origin behaviour; findings describe the edge, not the origin.",
    "Header absence is reported as a configuration observation; whether it matters depends on the app.",
    "Optional external tools (nuclei, httpx, subfinder, gitleaks, osv-scanner) are used only when present; "
    "native Python checks are the primary source of truth.",
    "Rate limits and timeouts are conservative by design for non-root mobile stability.",
]

_HEADER_BLOCK = re.compile(r"^(?:Response headers|GET \S+ -> \d+)$", re.M)

_CONF_SORT_RANK = {
    "CONFIRMED": 0,
    "STRONG EVIDENCE": 1,
    "HIGH CONFIDENCE": 1,
    "POTENTIAL": 2,
    "MEDIUM CONFIDENCE": 2,
    "LOW CONFIDENCE": 3,
    "NEEDS MANUAL VERIFICATION": 4,
}


def _trim_evidence(text, limit: int = 700) -> str:
    """Header dumps are long and repeated; keep a bounded slice."""
    text = str(text or "")
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]"


def split_markdown_chunks(markdown_text: str, max_chars: int = 100_000) -> list[str]:
    """K1: Split Markdown into chunks <= *max_chars* on finding/section boundaries, never mid-finding."""
    if len(markdown_text) <= max_chars:
        return [markdown_text]
    blocks = re.split(r"(?=\n### |\n## )", markdown_text)
    chunks: list[str] = []
    cur = ""
    for block in blocks:
        if cur and len(cur) + len(block) > max_chars:
            chunks.append(cur)
            cur = block.lstrip("\n")
        else:
            cur += block
    if cur:
        chunks.append(cur)
    return chunks or [markdown_text]


def compute_systemic_findings(findings_by_target: dict[str, list[dict]]) -> list[dict[str, Any]]:
    """P2 & P6: Emit systemic aggregate findings when >70% of targets share TLS 1.0/1.1 or missing CAA."""
    total_targets = len(findings_by_target)
    if total_targets == 0:
        return []
    tls_weak_hosts: list[str] = []
    caa_missing_hosts: list[str] = []
    for tgt, rows in findings_by_target.items():
        titles = " | ".join(str(r.get("title") or "") for r in rows).lower()
        if "tlsv1.0" in titles or "tlsv1.1" in titles or "deprecated tls" in titles:
            tls_weak_hosts.append(tgt)
        if "no caa record" in titles or "caa record absent" in titles:
            caa_missing_hosts.append(tgt)

    systemic: list[dict[str, Any]] = []
    if len(tls_weak_hosts) / total_targets > 0.70:
        systemic.append({
            "title": "Systemic finding: >70% of assessed hosts accept deprecated TLS 1.0/1.1",
            "severity": "MEDIUM",
            "affected_count": len(tls_weak_hosts),
            "total_targets": total_targets,
            "hosts": tls_weak_hosts,
        })
    if len(caa_missing_hosts) / total_targets > 0.70:
        systemic.append({
            "title": "Systemic finding: >70% of assessed zones lack CAA records",
            "severity": "LOW",
            "affected_count": len(caa_missing_hosts),
            "total_targets": total_targets,
            "hosts": caa_missing_hosts,
        })
    return systemic


def _counts(rows: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts


def _esc(value) -> str:
    return html.escape(str(value or ""))


def _is_manual_or_potential(row: dict[str, Any]) -> bool:
    vstat = str(row.get("verification_status") or "").upper()
    conf = str(row.get("confidence") or "").upper()
    return (
        vstat in ("NEEDS MANUAL VERIFICATION", "POTENTIAL", "MANUAL-REVIEW-REQUIRED")
        and conf not in ("CONFIRMED", "HIGH CONFIDENCE", "STRONG EVIDENCE")
    ) or conf in ("NEEDS MANUAL VERIFICATION", "LOW CONFIDENCE", "POTENTIAL", "HEURISTIC", "MANUAL REVIEW")


def _chip_class_for_verification(vstat: str, conf: str) -> str:
    v = (vstat or "").upper()
    c = (conf or "").upper()
    if v == "CONFIRMED" or c == "CONFIRMED":
        return "chip-confirmed"
    if v == "STRONG EVIDENCE" or c in ("HIGH CONFIDENCE", "STRONG EVIDENCE"):
        return "chip-strong"
    if v == "POTENTIAL" or c in ("MEDIUM CONFIDENCE", "POTENTIAL"):
        return "chip-potential"
    return "chip-manual"


def _normalize_finding_row(raw: dict[str, Any] | Finding, default_target: str = "") -> dict[str, Any]:
    """Ensure every finding dictionary carries both legacy keys and all 19 AI v2 schema keys."""
    if isinstance(raw, Finding):
        f_obj = raw
    elif isinstance(raw, dict):
        tgt = str(raw.get("target") or raw.get("target_url") or default_target or "")
        tags_val = raw.get("tags") or []
        if isinstance(tags_val, str):
            try:
                tags_val = json.loads(tags_val)
            except Exception:
                tags_val = []
        f_obj = Finding(
            target=tgt,
            category=str(raw.get("category") or "HTTP Security"),
            title=str(raw.get("title") or "Finding"),
            severity=str(raw.get("severity") or "INFO"),
            description=str(raw.get("description") or ""),
            evidence=str(raw.get("evidence") or ""),
            detection_method=str(raw.get("detection_method") or "Passive analysis"),
            confidence=str(raw.get("confidence") or "NEEDS MANUAL VERIFICATION"),
            cwe=raw.get("cwe") or raw.get("CWE"),
            cve=raw.get("cve") or raw.get("CVE"),
            remediation=str(raw.get("remediation") or ""),
            url=str(raw.get("url") or tgt),
            parameter=str(raw.get("parameter") or ""),
            module=str(raw.get("module") or ""),
            finding_id=str(raw.get("finding_id") or ""),
            timestamp=str(raw.get("timestamp") or raw.get("created_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")),
            verification_status=str(raw.get("verification_status") or "UNVERIFIED"),
            tags=list(tags_val) if isinstance(tags_val, list) else [],
            endpoint=str(raw.get("endpoint") or raw.get("url") or tgt),
            owasp_reference=str(raw.get("owasp_reference") or raw.get("OWASP_reference") or ""),
            wstg_reference=str(raw.get("wstg_reference") or raw.get("WSTG_reference") or ""),
            impact=str(raw.get("impact") or ""),
            false_positive_notes=str(raw.get("false_positive_notes") or ""),
            test_id=str(raw.get("test_id") or ""),
            edge=bool(raw.get("edge", False)),
            csp_source=str(raw.get("csp_source") or ""),
            check_outcome=str(raw.get("check_outcome") or "ran"),
            schema_version=str(raw.get("schema_version") or "2.0"),
            cvss=float(raw.get("cvss") or 0.0),
            evidence_hash=str(raw.get("evidence_hash") or ""),
            first_seen=str(raw.get("first_seen") or ""),
            last_seen=str(raw.get("last_seen") or ""),
        )
    else:
        raise TypeError(f"Unsupported finding type: {type(raw)}")

    out = f_obj.to_dict()
    out["target_url"] = f_obj.target
    if out.get("verification_status") not in ("CONFIRMED", "STRONG EVIDENCE", "POTENTIAL", "NEEDS MANUAL VERIFICATION"):
        out["verification_status"] = map_confidence_to_verification(
            out.get("confidence", ""), out.get("title", ""), out.get("evidence", "")
        )
    return out


def _fingerprint_from_dict(r: dict[str, Any], default_target: str = "") -> tuple[str, str, str, str]:
    mod = str(r.get("module") or r.get("category") or "")
    tgt = str(r.get("target") or r.get("target_url") or default_target or "")
    title = str(r.get("title") or "")
    param = str(r.get("parameter") or "")
    check = r.get("check") or (f"{title}|{param}" if param else title)
    if "evidence_digest" in r and r["evidence_digest"]:
        dig = str(r["evidence_digest"])
    else:
        ev = str(r.get("evidence") or "").encode("utf-8", "replace")
        dig = hashlib.sha256(ev).hexdigest()[:16]
    return (mod, tgt, str(check), dig)


def diff_scans(
    current_findings_by_target: dict[str, list[dict]],
    previous_json_path: Path | str,
) -> dict[str, Any]:
    """Compare current scan findings against a previous JSON report or baseline file (Item 14).

    Returns per-target ``new``, ``fixed``, and ``still_open`` lists plus aggregate totals.
    """
    prev_path = Path(previous_json_path)
    if not prev_path.exists():
        raise FileNotFoundError(f"Previous report not found: {prev_path}")
    prev_data = json.loads(prev_path.read_text(encoding="utf-8"))

    prev_by_target: dict[str, dict[tuple[str, str, str, str], dict[str, Any]]] = {}
    if isinstance(prev_data, dict):
        if "findings" in prev_data and isinstance(prev_data["findings"], list):
            for item in prev_data["findings"]:
                if isinstance(item, dict):
                    tgt = str(item.get("target") or item.get("target_url") or "unknown")
                    fp = _fingerprint_from_dict(item, tgt)
                    prev_by_target.setdefault(tgt, {})[fp] = item
        elif "entries" in prev_data and isinstance(prev_data["entries"], list):
            for item in prev_data["entries"]:
                if isinstance(item, dict):
                    tgt = str(item.get("target") or "unknown")
                    fp = _fingerprint_from_dict(item, tgt)
                    prev_by_target.setdefault(tgt, {})[fp] = item

    curr_by_target: dict[str, dict[tuple[str, str, str, str], dict[str, Any]]] = {}
    for tgt, rows in current_findings_by_target.items():
        curr_map: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for r in rows:
            norm = _normalize_finding_row(r, tgt)
            fp = _fingerprint_from_dict(norm, tgt)
            curr_map[fp] = norm
        curr_by_target[tgt] = curr_map

    all_targets = sorted(set(prev_by_target.keys()) | set(curr_by_target.keys()))
    per_target: dict[str, dict[str, list[dict[str, Any]]]] = {}
    totals = {"new": 0, "fixed": 0, "still_open": 0}

    for tgt in all_targets:
        p_map = prev_by_target.get(tgt, {})
        c_map = curr_by_target.get(tgt, {})
        new_fps = [fp for fp in c_map if fp not in p_map]
        fixed_fps = [fp for fp in p_map if fp not in c_map]
        open_fps = [fp for fp in c_map if fp in p_map]

        new_list = [c_map[fp] for fp in new_fps]
        fixed_list = [p_map[fp] for fp in fixed_fps]
        open_list = [c_map[fp] for fp in open_fps]

        per_target[tgt] = {
            "new": new_list,
            "fixed": fixed_list,
            "still_open": open_list,
        }
        totals["new"] += len(new_list)
        totals["fixed"] += len(fixed_list)
        totals["still_open"] += len(open_list)

    return {
        "previous_file": str(prev_path),
        "targets": per_target,
        "totals": totals,
    }


class ReportManager:
    def __init__(self, base_dir: Path, template_path: Path):
        self.base = Path(base_dir)
        self.template_path = Path(template_path)
        for sub in ("html", "json", "jsonl", "md", "txt", "csv", "sarif", "ai_packages"):
            (self.base / sub).mkdir(parents=True, exist_ok=True)

    # ---- helpers ---------------------------------------------------------
    @staticmethod
    def _as_target_dict(target) -> dict:
        if isinstance(target, dict):
            return dict(target)
        return {
            "url": target.url,
            "status": "done" if getattr(target, "ok", True) else "failed",
            "state": getattr(target, "state", "COMPLETE"),
            "score": getattr(target, "score", 100),
            "score_display": getattr(target, "score_display", str(getattr(target, "score", 100))),
            "grade": getattr(target, "grade", "A"),
            "request_count": getattr(target, "requests", 0),
            "duration_s": getattr(target, "elapsed_s", 0),
            "error": getattr(target, "error", "") or None,
            "edge_banner": getattr(target, "edge_banner", ""),
            "edge_challenged": getattr(target, "edge_challenged", False),
            "checks_account": getattr(target, "checks_account", {"ran": 0, "skipped": 0, "failed": 0}),
        }

    def _slug(self, url: str) -> str:
        return re.sub(r"[^A-Za-z0-9]+", "_", url.replace("://", "_"))[:90].strip("_") or "target"

    def _path(self, fmt: str, name: str, ext: str | None = None) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        suffix = ext or fmt
        return self.base / fmt / f"{stamp}_{name}.{suffix}"

    @staticmethod
    def mean_target_score(findings_by_target: dict, targets: list | None = None) -> dict:
        """J1, J2, D4: Compute global score (min when CRITICAL exists, else mean of COMPLETE targets)."""
        excluded_urls: set[str] = set()
        if targets:
            for t in targets:
                st = (t.get("state") if isinstance(t, dict) else getattr(t, "state", "COMPLETE")) or "COMPLETE"
                u = (t.get("url") if isinstance(t, dict) else getattr(t, "url", "")) or ""
                if st in ("INCOMPLETE", "PARTIAL"):
                    excluded_urls.add(u)

        all_counts = {s: 0 for s in SEVERITY_ORDER}
        per_target_scores: list[int] = []
        for tgt_url, rows in findings_by_target.items():
            c = _counts(rows)
            for s_key, cnt in c.items():
                all_counts[s_key] = all_counts.get(s_key, 0) + cnt
            if any(str(r.get("title") or "") == "TARGET_UNREACHABLE" for r in rows):
                continue
            if tgt_url in excluded_urls:
                continue
            v, _ = score_counts(c)
            per_target_scores.append(v)

        if not per_target_scores and not any(all_counts.values()):
            return {
                "score": 100,
                "grade": "A",
                "counts": all_counts,
                "total": 0,
                "breakdown": score_breakdown(all_counts),
            }
        val, grade = compute_global_score(
            per_target_scores,
            has_critical=(all_counts.get("CRITICAL", 0) > 0),
            total_counts=all_counts,
        )
        return {
            "score": val,
            "grade": grade,
            "counts": all_counts,
            "total": sum(all_counts.values()),
            "breakdown": score_breakdown(all_counts),
        }

    @staticmethod
    def summarize(rows: list[dict]) -> dict:
        counts = _counts(rows)
        value, grade = score_counts(counts)
        return {"counts": counts, "score": value, "grade": grade, "total": len(rows)}

    def _build_json_payload(self, scan_meta: dict, targets: list,
                            findings_by_target: dict[str, list[dict]]) -> dict[str, Any]:
        target_dicts = [self._as_target_dict(t) for t in targets]
        norm_by_target: dict[str, list[dict[str, Any]]] = {
            t["url"]: [_normalize_finding_row(r, t["url"]) for r in findings_by_target.get(t["url"], [])]
            for t in target_dicts
        }
        for k, rows in findings_by_target.items():
            if k not in norm_by_target:
                norm_by_target[k] = [_normalize_finding_row(r, k) for r in rows]

        all_rows = [f for rows in norm_by_target.values() for f in rows]
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        rep_id = str(scan_meta.get("id") or f"tsmss-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
        target_inv = [
            dict(t, summary=self.summarize(norm_by_target.get(t["url"], [])))
            for t in target_dicts
        ]
        return {
            # Section 15 AI-Readable required top-level metadata
            "schema_version": "2.0",
            "report_id": rep_id,
            "scanner_version": "2.0.0",
            "report_timestamp": now_iso,
            "target_inventory": target_inv,
            "scan_scope": scan_meta.get("scope", {"authorized": True, "targets": [t["url"] for t in target_dicts]}),
            "methodology": SCORE_METHOD,
            "score_breakdown": score_breakdown(_counts(all_rows)),
            "systemic_findings": compute_systemic_findings(norm_by_target),
            "standards_versions": dict(STANDARDS_VERSIONS),
            "limitations": list(LIMITATIONS),
            "findings": all_rows,
            # Legacy v1 keys preserved for backward compatibility
            "tool": "TSMSS",
            "schema": "2.0",
            "generated_at": now_iso,
            "scan": scan_meta,
            "summary": self.summarize(all_rows),
            "targets": target_inv,
            "findings_by_target": norm_by_target,
        }

    # ---- JSON & JSONL ----------------------------------------------------
    def json_report(self, scan_meta: dict, targets: list,
                    findings_by_target: dict[str, list[dict]]) -> Path:
        payload = self._build_json_payload(scan_meta, targets, findings_by_target)
        path = self._path("json", "combined")
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def json_target(self, target, rows: list[dict]) -> Path:
        td = self._as_target_dict(target)
        norm_rows = [_normalize_finding_row(r, td["url"]) for r in rows]
        path = self._path("json", self._slug(td["url"]))
        path.write_text(json.dumps({
            "target": td,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": self.summarize(norm_rows),
            "findings": norm_rows,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def jsonl_report(self, scan_meta: dict, targets: list,
                     findings_by_target: dict[str, list[dict]]) -> Path:
        payload = self._build_json_payload(scan_meta, targets, findings_by_target)
        path = self._path("jsonl", "combined", "jsonl")
        with path.open("w", encoding="utf-8") as fh:
            for f in payload["findings"]:
                row = dict(f)
                row["report_id"] = payload["report_id"]
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        return path

    # ---- SARIF v2.1.0 (Item 15 & Section 14) -----------------------------
    def sarif_report(self, scan_meta: dict, targets: list,
                     findings_by_target: dict[str, list[dict]]) -> Path:
        payload = self._build_json_payload(scan_meta, targets, findings_by_target)
        all_rows = payload["findings"]
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        sev_to_sarif = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }

        for f in all_rows:
            rule_id = str(f.get("test_id") or f.get("CWE") or f.get("category") or "TSMSS-GEN-001")
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": str(f.get("title") or rule_id)[:120],
                    "shortDescription": {"text": str(f.get("title") or "")},
                    "fullDescription": {"text": str(f.get("description") or f.get("title") or "")},
                    "help": {"text": str(f.get("remediation") or "Review finding remediation.")},
                    "properties": {
                        "category": f.get("category"),
                        "owasp": f.get("OWASP_reference"),
                        "wstg": f.get("WSTG_reference"),
                        "cwe": f.get("CWE"),
                    },
                }

            mod, tgt, chk, dig = _fingerprint_from_dict(f)
            uri = str(f.get("endpoint") or f.get("url") or f.get("target") or "https://localhost/")
            results.append({
                "ruleId": rule_id,
                "level": sev_to_sarif.get(str(f.get("severity", "INFO")).upper(), "note"),
                "message": {
                    "text": f"[{f.get('severity')}] {f.get('title')}: {f.get('description')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                        }
                    }
                ],
                "partialFingerprints": {
                    "tsmssFingerprint/v1": f"{mod}|{tgt}|{chk}|{dig}",
                },
                "properties": {
                    "finding_id": f.get("finding_id"),
                    "severity": f.get("severity"),
                    "confidence": f.get("confidence"),
                    "verification_status": f.get("verification_status"),
                    "parameter": f.get("parameter"),
                    "evidence": _trim_evidence(f.get("evidence"), 500),
                    "owasp_reference": f.get("OWASP_reference"),
                    "wstg_reference": f.get("WSTG_reference"),
                    "cwe": f.get("CWE"),
                    "cve": f.get("CVE"),
                },
            })

        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TSMSS",
                            "fullName": "Termux Super Master Security Scanner 2.0 Ultimate Edition",
                            "semanticVersion": "2.0.0",
                            "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "automationDetails": {
                        "id": f"tsmss/{payload['report_id']}",
                    },
                    "results": results,
                }
            ],
        }
        path = self._path("sarif", "combined", "sarif.json")
        path.write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    # ---- Markdown (Section 14, Section 15 & Work Item K) -----------------
    def markdown_report(self, scan_meta: dict, targets: list,
                        findings_by_target: dict[str, list[dict]],
                        max_chars: int = 100_000) -> Path:
        payload = self._build_json_payload(scan_meta, targets, findings_by_target)
        s = self.mean_target_score(payload["findings_by_target"], payload["target_inventory"])
        buf = io.StringIO()
        w = buf.write
        w(f"# TSMSS 2.0 Security Assessment Report (`{payload['report_id']}`)\n\n")
        w(f"- **Generated**: `{payload['report_timestamp']}`\n")
        w(f"- **Overall Score**: **{s['score']}/100** (Grade **{s['grade']}**)\n")
        w(f"- **Targets Assessed**: {len(payload['target_inventory'])}\n")
        w(f"- **Total Findings**: {s['total']} (" + ", ".join(f"{k}: {v}" for k, v in s["counts"].items()) + ")\n\n")

        # J3: Weight / deduction table in report header
        w("## Score Weight & Deduction Table\n\n")
        w("| Severity | Count | Cap | Saturation (k) | Deduction |\n")
        w("| :--- | :---: | :---: | :---: | :---: |\n")
        for b in s.get("breakdown", []):
            w(f"| {b['severity']} | {b['count']} | {b['cap']} | {b['k']} | -{b['deduction']} |\n")

        systemic = payload.get("systemic_findings") or []
        if systemic:
            w("\n## Systemic Findings\n\n")
            for sf in systemic:
                w(f"- **[{sf['severity']}] {sf['title']}** ({sf['affected_count']}/{sf['total_targets']} hosts)\n")

        w("\n## Standards Alignment\n")
        for k, v in STANDARDS_VERSIONS.items():
            w(f"- `{k}`: `{v}`\n")

        w("\n## Target Summary\n\n")
        w("| Target | Status | State | Score | Grade | Findings |\n")
        w("| :--- | :--- | :---: | :---: | :---: | :---: |\n")
        for t in payload["target_inventory"]:
            ts = t["summary"]
            st = t.get("state") or "COMPLETE"
            sc_disp = "INCOMPLETE" if st == "INCOMPLETE" else (t.get("score_display") or str(ts["score"]))
            gr_disp = "INCOMPLETE" if st == "INCOMPLETE" else ts["grade"]
            w(f"| `{t['url']}` | {t.get('status')} | {st} | {sc_disp} | **{gr_disp}** | {ts['total']} |\n")

        # K2 & K4: Per-target header block once + Verification section splitting Confirmed vs NEEDS MANUAL VERIFICATION
        for t in payload["target_inventory"]:
            t_url = t["url"]
            t_rows = sorted(
                payload["findings_by_target"].get(t_url, []),
                key=lambda x: severity_rank(x["severity"]),
            )
            w(f"\n## Target: `{t_url}`\n")
            if t.get("edge_banner"):
                w(f"> **Banner**: `{t['edge_banner']}`\n\n")
            # Emit response header block ONCE per target if captured
            hdr_block = None
            for f in t_rows:
                ev = str(f.get("evidence") or "")
                if ev.startswith("Response headers"):
                    hdr_block = ev
                    break
            if hdr_block:
                w(f"\n### Response Headers (`{t_url}`)\n```text\n{_trim_evidence(hdr_block, 600)}\n```\n")

            t_confirmed = [f for f in t_rows if not _is_manual_or_potential(f)]
            t_manual = [f for f in t_rows if _is_manual_or_potential(f)]

            w(f"\n### Verification — Machine-Confirmed Findings ({len(t_confirmed)})\n")
            if not t_confirmed:
                w("\n_No machine-confirmed findings for this target._\n")
            for f in t_confirmed:
                w(f"\n### [{f['severity']}] {f['title']} (`{f['finding_id']}`)\n")
                w(f"- **Target**: `{f['target']}` (`{f['endpoint']}`)\n")
                w(f"- **Verification Status**: `{f['verification_status']}` (`{f['confidence']}`)\n")
                w(f"- **OWASP / WSTG / CWE**: {f['OWASP_reference']} | {f['WSTG_reference']} | `{f.get('CWE') or 'N/A'}`\n")
                if f.get("parameter"):
                    w(f"- **Parameter**: `{f['parameter']}`\n")
                w(f"- **Description**: {f['description']}\n")
                w(f"- **Remediation**: {f['remediation']}\n")
                ev = str(f.get("evidence") or "")
                if ev and not ev.startswith("Response headers"):
                    w(f"\n```text\n{_trim_evidence(ev, 400)}\n```\n")

            w(f"\n### Verification — Needs Manual Verification ({len(t_manual)})\n")
            if not t_manual:
                w("\n_No manual-verification findings for this target._\n")
            for f in t_manual:
                w(f"\n### [{f['severity']}] {f['title']} (`{f['finding_id']}`)\n")
                w(f"- **Target**: `{f['target']}` | **Verification**: `{f['verification_status']}`\n")
                w(f"- **False-Positive Notes**: {f['false_positive_notes']}\n")
                w(f"- **Remediation**: {f['remediation']}\n")

        w("\n## Scan Limitations\n")
        for lim in LIMITATIONS:
            w(f"- {lim}\n")

        full_md = buf.getvalue()
        chunks = split_markdown_chunks(full_md, max_chars=max_chars)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = self._path("md", "combined", "md")
        path.write_text(full_md, encoding="utf-8")

        if len(chunks) > 1:
            part_files: list[str] = []
            for idx, chunk in enumerate(chunks, start=1):
                part_name = f"report_{stamp}_{idx}.md"
                part_path = self.base / "md" / part_name
                part_path.write_text(chunk, encoding="utf-8")
                part_files.append(part_name)
            idx_lines = [
                f"# TSMSS Report Index (`{payload['report_id']}`)",
                "",
                f"Split into {len(part_files)} parts (<= {max_chars} chars each, never truncated mid-finding):",
                "",
            ]
            for idx, pname in enumerate(part_files, start=1):
                idx_lines.append(f"- [Part {idx}: `{pname}`]({pname})")
            index_path = self.base / "md" / "index.md"
            index_path.write_text("\n".join(idx_lines) + "\n", encoding="utf-8")

        return path

    # ---- AI Upload Package (Section 15) ----------------------------------
    def ai_package_report(self, scan_meta: dict, targets: list,
                          findings_by_target: dict[str, list[dict]]) -> dict[str, Any]:
        payload = self._build_json_payload(scan_meta, targets, findings_by_target)
        pkg_dir = self.base / "ai_packages" / str(payload["report_id"])
        schema_file = Path(__file__).resolve().parent.parent / "schemas" / "tsmss-report-v2.schema.json"
        return build_ai_upload_package(payload, pkg_dir, schema_path=schema_file)

    # ---- CSV -------------------------------------------------------------
    FIELDS = [
        "finding_id", "target_url", "endpoint", "category", "title", "severity",
        "confidence", "verification_status", "parameter", "cwe", "cve",
        "owasp_reference", "wstg_reference", "detection_method",
        "description", "evidence", "remediation", "timestamp",
    ]

    def csv_report(self, rows: list[dict]) -> Path:
        norm = [_normalize_finding_row(r) for r in rows]
        path = self._path("csv", "combined")
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=self.FIELDS, extrasaction="ignore")
            w.writeheader()
            for r in sorted(norm, key=lambda x: severity_rank(x["severity"])):
                w.writerow({k: (r.get(k) or "") for k in self.FIELDS})
        return path

    # ---- TXT -------------------------------------------------------------
    def txt_report(self, scan_meta: dict, targets: list,
                   findings_by_target: dict[str, list[dict]]) -> Path:
        targets = [self._as_target_dict(t) for t in targets]
        buf = io.StringIO()
        s = self.mean_target_score(findings_by_target)
        w = buf.write
        w("=" * 78 + "\nTSMSS 2.0 SECURITY ASSESSMENT REPORT\n" + "=" * 78 + "\n")
        w(f"Scan ID     : {scan_meta.get('id')}\n")
        w(f"Generated   : {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
        w(f"Targets     : {len(targets)}\n")
        w(f"Findings    : {s['total']}\n")
        w(f"Score       : {s['score']}/100 (grade {s['grade']})\n")
        w("Severity    : " + ", ".join(f"{k}={v}" for k, v in s["counts"].items()) + "\n")
        w("\nSCORING\n" + SCORE_METHOD + "\n")
        w("\nLIMITATIONS\n" + "\n".join(f"- {x}" for x in LIMITATIONS) + "\n")
        for t in targets:
            rows = sorted(
                [_normalize_finding_row(r, t["url"]) for r in findings_by_target.get(t["url"], [])],
                key=lambda x: severity_rank(x["severity"]),
            )
            ts = self.summarize(rows)
            w("\n" + "-" * 78 + f"\nTARGET: {t['url']}\nStatus: {t.get('status')}  "
              f"Score: {ts['score']} ({ts['grade']})\n" + "-" * 78 + "\n")
            if not rows:
                w("  No findings.\n")
            for f in rows:
                w(f"\n[{f['severity']}] {f['finding_id']} {f['title']}\n")
                w(f"  Confidence : {f['confidence']}  ({f['verification_status']})\n")
                w(f"  Category   : {f['category']} | {f.get('owasp_reference', '')}\n")
                if f.get("parameter"):
                    w(f"  Parameter  : {f['parameter']}\n")
                if f.get("cwe"):
                    w(f"  CWE        : {f['cwe']}\n")
                w(f"  Method     : {f['detection_method']}\n")
                w(f"  Description: {f['description']}\n")
                if f.get("evidence"):
                    w("  Evidence   :\n")
                    for line in str(f["evidence"]).splitlines()[:20]:
                        w(f"    | {line}\n")
                if f.get("remediation"):
                    w(f"  Remediation: {f['remediation']}\n")
        path = self._path("txt", "combined")
        path.write_text(buf.getvalue(), encoding="utf-8")
        return path

    def txt_target(self, target, rows: list[dict]) -> Path:
        target = self._as_target_dict(target)
        norm_rows = [_normalize_finding_row(r, target["url"]) for r in rows]
        buf = io.StringIO()
        s = self.summarize(norm_rows)
        buf.write(f"TARGET: {target['url']}\nScore: {s['score']} ({s['grade']})\n\n")
        for f in sorted(norm_rows, key=lambda x: severity_rank(x["severity"])):
            buf.write(f"[{f['severity']}] {f['title']} ({f['confidence']} / {f['verification_status']})\n"
                      f"  {f['description']}\n  Evidence: {str(f.get('evidence'))[:400]}\n"
                      f"  Fix: {f['remediation']}\n\n")
        path = self._path("txt", self._slug(target["url"]))
        path.write_text(buf.getvalue(), encoding="utf-8")
        return path

    # ---- HTML (Item 18 & Section 14) -------------------------------------
    def _render_card(self, f: dict[str, Any], target_url: str) -> str:
        sev_low = _esc(f["severity"].lower())
        vstat = str(f.get("verification_status") or "NEEDS MANUAL VERIFICATION")
        conf = str(f.get("confidence") or "NEEDS MANUAL VERIFICATION")
        chip_cls = _chip_class_for_verification(vstat, conf)
        conf_chip_html = f'<span class="chip {chip_cls}">{_esc(conf)}</span>' if conf.upper() != vstat.upper() else ""
        return f"""
<article class="card filterable-item sev-border-{sev_low}" data-sev="{_esc(f['severity'])}" data-target="{_esc(target_url)}" data-vstat="{_esc(vstat)}" data-conf="{_esc(conf)}">
  <header>
    <span class="sev sev-{sev_low}">{_esc(f['severity'])}</span>
    <span class="chip {chip_cls}">{_esc(vstat)}</span>
    {conf_chip_html}
    <span class="fid">{_esc(f['finding_id'])}</span>
    <h4>{_esc(f['title'])}</h4>
  </header>
  <dl>
    <dt>Category</dt><dd>{_esc(f['category'])}</dd>
    <dt>OWASP / WSTG</dt><dd>{_esc(f.get('owasp_reference'))} &middot; <code>{_esc(f.get('wstg_reference'))}</code></dd>
    <dt>Detection</dt><dd>{_esc(f['detection_method'])}</dd>
    {f"<dt>Parameter</dt><dd><code>{_esc(f['parameter'])}</code></dd>" if f.get('parameter') else ""}
    {f"<dt>CWE</dt><dd><code>{_esc(f['cwe'])}</code></dd>" if f.get('cwe') else ""}
    {f"<dt>CVE</dt><dd><code>{_esc(f['cve'])}</code></dd>" if f.get('cve') else ""}
  </dl>
  <p class="desc">{_esc(f['description'])}</p>
  {f'<details><summary>Evidence Snippet</summary><pre>{_esc(_trim_evidence(f["evidence"]))}</pre></details>' if f.get('evidence') else ""}
  <p class="fix"><strong>Remediation:</strong> {_esc(f['remediation'])}</p>
</article>"""

    def html_report(self, scan_meta: dict, targets: list,
                    findings_by_target: dict[str, list[dict]]) -> Path:
        targets = [self._as_target_dict(t) for t in targets]
        norm_by_target: dict[str, list[dict[str, Any]]] = {
            t["url"]: [_normalize_finding_row(r, t["url"]) for r in findings_by_target.get(t["url"], [])]
            for t in targets
        }
        s = self.mean_target_score(norm_by_target)
        template = Template(self.template_path.read_text(encoding="utf-8"))

        target_rows = "\n".join(
            f"<tr><td>{_esc(t['url'])}</td><td class='st st-{_esc(t.get('status'))}'>"
            f"{_esc(t.get('status'))}</td>"
            f"<td>{self.summarize(norm_by_target.get(t['url'], []))['score']}</td>"
            f"<td>{len(norm_by_target.get(t['url'], []))}</td></tr>"
            for t in targets
        )

        severity_rows = "\n".join(
            f"<tr><td><span class='sev sev-{k.lower()}'>{k}</span></td>"
            f"<td>{s['counts'][k]}</td></tr>"
            for k in SEVERITY_ORDER
        )

        # Target Tabs
        tabs_html = [
            f"<button type='button' class='tab-btn active' data-target='ALL' onclick=\"setTargetTab('ALL', this)\">All Targets ({len(targets)})</button>"
        ]
        for t in targets:
            t_rows = norm_by_target.get(t["url"], [])
            ts = self.summarize(t_rows)
            tabs_html.append(
                f"<button type='button' class='tab-btn' data-target='{_esc(t['url'])}' onclick=\"setTargetTab('{_esc(t['url'])}', this)\">"
                f"{_esc(t['url'])} [{ts['grade']}: {len(t_rows)}]</button>"
            )

        table_rows_html: list[str] = []
        confirmed_sections: list[str] = []
        manual_sections: list[str] = []
        confirmed_total = 0
        manual_total = 0

        for t in targets:
            t_url = t["url"]
            rows = sorted(norm_by_target.get(t_url, []), key=lambda x: severity_rank(x["severity"]))
            ts = self.summarize(rows)
            conf_cards: list[str] = []
            man_cards: list[str] = []

            for f in rows:
                sev = f["severity"]
                sev_rank_num = severity_rank(sev)
                vstat = str(f.get("verification_status") or "NEEDS MANUAL VERIFICATION")
                conf = str(f.get("confidence") or "NEEDS MANUAL VERIFICATION")
                conf_rank_num = _CONF_SORT_RANK.get(vstat.upper(), _CONF_SORT_RANK.get(conf.upper(), 4))
                chip_cls = _chip_class_for_verification(vstat, conf)

                param_html = f"<code>{_esc(f['parameter'])}</code>" if f.get("parameter") else "&mdash;"
                table_rows_html.append(
                    f"<tr class='filterable-item' data-sev='{_esc(sev)}' data-target='{_esc(t_url)}' data-vstat='{_esc(vstat)}' data-conf='{_esc(conf)}'>"
                    f"<td data-rank='{sev_rank_num}'><span class='sev sev-{_esc(sev.lower())}'>{_esc(sev)}</span></td>"
                    f"<td data-rank='{conf_rank_num}'><span class='chip {chip_cls}'>{_esc(vstat)}</span><br><small style='color:var(--dim)'>{_esc(conf)}</small></td>"
                    f"<td><code>{_esc(t_url)}</code></td>"
                    f"<td>{_esc(f['category'])}<br><small style='color:var(--dim)'>{_esc(f.get('owasp_reference'))}</small></td>"
                    f"<td><strong>{_esc(f['title'])}</strong><br><small style='color:var(--dim)'>{_esc(f['description'][:160])}</small></td>"
                    f"<td>{param_html}<br><small>{_esc(f.get('cwe') or '')}</small></td>"
                    f"</tr>"
                )

                card_html = self._render_card(f, t_url)
                if _is_manual_or_potential(f):
                    manual_total += 1
                    man_cards.append(card_html)
                else:
                    confirmed_total += 1
                    conf_cards.append(card_html)

            if not conf_cards:
                conf_cards.append("<p class='clean'>No confirmed or strong-evidence findings for this target.</p>")
            confirmed_sections.append(f"""
<section class="target target-block" data-target="{_esc(t_url)}">
  <h3>{_esc(t_url)}
    <span class="grade g-{ts['grade'].lower()}">{ts['score']} / {ts['grade']}</span></h3>
  <p class="meta">Status: {_esc(t.get('status'))} &middot; Requests: {t.get('request_count', 0)}
     &middot; Duration: {t.get('duration_s', 0)}s</p>
  {''.join(conf_cards)}
</section>""")

            if man_cards:
                manual_sections.append(f"""
<section class="target target-block" data-target="{_esc(t_url)}">
  <h3>{_esc(t_url)} <span class="chip chip-manual">{len(man_cards)} manual-review item(s)</span></h3>
  {''.join(man_cards)}
</section>""")

        if not manual_sections:
            manual_sections.append("<p class='clean'>No findings require separate manual verification.</p>")

        exec_summary = (
            f"{len(targets)} authorized target(s) were assessed with non-destructive OWASP-aligned checks. "
            f"{s['total']} finding(s) were recorded ({confirmed_total} confirmed/strong-evidence, "
            f"{manual_total} potential/manual-verification): "
            f"{s['counts']['CRITICAL']} critical, {s['counts']['HIGH']} high, "
            f"{s['counts']['MEDIUM']} medium, {s['counts']['LOW']} low, "
            f"{s['counts']['INFO']} informational. Overall score {s['score']}/100 "
            f"(grade {s['grade']}). "
            + ("Critical items should be triaged immediately."
               if s["counts"]["CRITICAL"] else
               "No critical items were identified by automated checks.")
        )

        out = template.safe_substitute(
            generated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            scan_id=_esc(scan_meta.get("id")),
            note=_esc(scan_meta.get("note", "")),
            executive_summary=_esc(exec_summary),
            score=s["score"],
            grade=s["grade"],
            grade_class=f"g-{s['grade'].lower()}",
            severity_rows=severity_rows,
            target_rows=target_rows,
            target_tabs="\n".join(tabs_html),
            table_rows="\n".join(table_rows_html),
            total_findings=s["total"],
            confirmed_count=confirmed_total,
            manual_count=manual_total,
            target_count=len(targets),
            methodology=_esc(SCORE_METHOD).replace("\n", "<br>"),
            limitations="".join(f"<li>{_esc(x)}</li>" for x in LIMITATIONS),
            sections="".join(confirmed_sections),
            manual_sections="".join(manual_sections),
        )
        path = self._path("html", "combined")
        path.write_text(out, encoding="utf-8")
        return path

    def html_target(self, scan_meta: dict, target, rows: list[dict]) -> Path:
        td = self._as_target_dict(target)
        return self.html_report(scan_meta, [td], {td["url"]: rows})

    # ---- batch writer ----------------------------------------------------
    def write_target_reports(self, scan_meta: dict, target, rows: list[dict]) -> dict:
        td = self._as_target_dict(target)
        return {
            "json": str(self.json_target(td, rows)),
            "txt": str(self.txt_target(td, rows)),
            "html": str(self.html_target(scan_meta, td, rows)),
        }
