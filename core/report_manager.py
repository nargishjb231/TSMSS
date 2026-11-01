"""Report rendering: HTML, JSON, TXT, CSV — per target and combined."""
from __future__ import annotations

import csv
import html
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from string import Template

from config import SEVERITY_ORDER, SEVERITY_WEIGHTS
from core.finding import score_counts, severity_rank

SCORE_METHOD = """Each severity contributes a saturating deduction
cap * n / (n + k): CRITICAL cap 90 k 3, HIGH cap 25 k 5, MEDIUM cap 12 k 8,
LOW cap 5 k 15, INFO 0. Score = max(0, 100 - total). Caps stop a noisy target
from flooring at 0 while repeats still cost less than first occurrences.
Grades: A>=90, B>=80, C>=65, D>=50, E>=30, F<30. A relative prioritisation
aid, not a compliance verdict; absence of findings is not proof of security."""

LIMITATIONS = [
    "Non-destructive black-box testing only; no authenticated crawling, exploitation, "
    "account creation or write operations.",
    "Single-entry-point crawl. Deep paths, SPA routes and authenticated areas are under-sampled.",
    "Vulnerability classes that need state (IDOR, SSRF, file upload, business logic) are "
    "indicated heuristically and require manual confirmation.",
    "CDN/WAF edges may mask origin behaviour; findings describe the edge, not the origin.",
    "Header absence is reported as an observation; whether it matters depends on the app.",
    "Go-based accelerators (nuclei, httpx, subfinder) are used only when present; the native "
    "Python checks are the source of truth.",
    "Rate limits and timeouts are conservative by design; large targets may be truncated.",
]


_HEADER_BLOCK = re.compile(r"^(?:Response headers|GET \S+ -> \d+)$", re.M)


def _trim_evidence(text, limit: int = 700) -> str:
    """Header dumps are long and repeated; keep a bounded slice."""
    text = str(text or "")
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]"


def _counts(rows: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts


def _esc(value) -> str:
    return html.escape(str(value or ""))


class ReportManager:
    def __init__(self, base_dir: Path, template_path: Path):
        self.base = Path(base_dir)
        self.template_path = Path(template_path)
        for sub in ("html", "json", "txt", "csv"):
            (self.base / sub).mkdir(parents=True, exist_ok=True)

    # ---- helpers ---------------------------------------------------------
    def _slug(self, url: str) -> str:
        return re.sub(r"[^A-Za-z0-9]+", "_", url.replace("://", "_"))[:90].strip("_") or "target"

    def _path(self, fmt: str, name: str) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return self.base / fmt / f"{stamp}_{name}.{fmt}"

    @staticmethod
    def mean_target_score(findings_by_target: dict) -> dict:
        """Batch score is the mean of per-target scores, never a sum."""
        scores = [score_counts(_counts(rows)) for rows in findings_by_target.values()]
        if not scores:
            return {"score": 100, "grade": "A", "counts": {s: 0 for s in SEVERITY_ORDER},
                    "total": 0}
        mean = round(sum(v for v, _ in scores) / len(scores))
        worst = min(g for _, g in scores)
        all_counts = {s: 0 for s in SEVERITY_ORDER}
        for rows in findings_by_target.values():
            for r in rows:
                all_counts[r["severity"]] += 1
        return {"score": mean, "grade": worst, "counts": all_counts,
                "total": sum(all_counts.values())}

    @staticmethod
    def summarize(rows: list[dict]) -> dict:
        counts = _counts(rows)
        value, grade = score_counts(counts)
        return {"counts": counts, "score": value, "grade": grade, "total": len(rows)}

    # ---- JSON ------------------------------------------------------------
    def json_report(self, scan_meta: dict, targets: list[dict],
                    findings_by_target: dict[str, list[dict]]) -> Path:
        all_rows = [f for rows in findings_by_target.values() for f in rows]
        payload = {
            "tool": "TSMSS", "schema": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scan": scan_meta,
            "methodology": SCORE_METHOD,
            "limitations": LIMITATIONS,
            "summary": self.summarize(all_rows),
            "targets": [dict(t, summary=self.summarize(findings_by_target.get(t["url"], [])))
                        for t in targets],
            "findings": all_rows,
        }
        path = self._path("json", "combined")
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def json_target(self, target: dict, rows: list[dict]) -> Path:
        path = self._path("json", self._slug(target["url"]))
        path.write_text(json.dumps({
            "target": target, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": self.summarize(rows), "findings": rows}, indent=2, ensure_ascii=False),
            encoding="utf-8")
        return path

    # ---- CSV -------------------------------------------------------------
    FIELDS = ["finding_id", "target_url", "category", "title", "severity", "confidence",
              "verification_status", "parameter", "cwe", "cve", "detection_method",
              "description", "evidence", "remediation", "timestamp"]

    def csv_report(self, rows: list[dict]) -> Path:
        path = self._path("csv", "combined")
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=self.FIELDS, extrasaction="ignore")
            w.writeheader()
            for r in sorted(rows, key=lambda x: severity_rank(x["severity"])):
                w.writerow({k: (r.get(k) or "") for k in self.FIELDS})
        return path

    # ---- TXT -------------------------------------------------------------
    def txt_report(self, scan_meta: dict, targets: list[dict],
                   findings_by_target: dict[str, list[dict]]) -> Path:
        buf = io.StringIO()
        all_rows = [f for rows in findings_by_target.values() for f in rows]
        s = self.mean_target_score(findings_by_target)
        w = buf.write
        w("=" * 78 + "\nTSMSS SECURITY ASSESSMENT REPORT\n" + "=" * 78 + "\n")
        w(f"Scan ID     : {scan_meta.get('id')}\n")
        w(f"Generated   : {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
        w(f"Targets     : {len(targets)}\n")
        w(f"Findings    : {s['total']}\n")
        w(f"Score       : {s['score']}/100 (grade {s['grade']})\n")
        w("Severity    : " + ", ".join(f"{k}={v}" for k, v in s["counts"].items()) + "\n")
        w("\nSCORING\n" + SCORE_METHOD + "\n")
        w("\nLIMITATIONS\n" + "\n".join(f"- {x}" for x in LIMITATIONS) + "\n")
        for t in targets:
            rows = sorted(findings_by_target.get(t["url"], []), key=lambda x: severity_rank(x["severity"]))
            ts = self.summarize(rows)
            w("\n" + "-" * 78 + f"\nTARGET: {t['url']}\nStatus: {t.get('status')}  "
              f"Score: {ts['score']} ({ts['grade']})\n" + "-" * 78 + "\n")
            if not rows:
                w("  No findings.\n")
            for f in rows:
                w(f"\n[{f['severity']}] {f['finding_id']} {f['title']}\n")
                w(f"  Confidence : {f['confidence']}  ({f['verification_status']})\n")
                w(f"  Category   : {f['category']}\n")
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

    def txt_target(self, target: dict, rows: list[dict]) -> Path:
        buf = io.StringIO()
        s = self.summarize(rows)
        buf.write(f"TARGET: {target['url']}\nScore: {s['score']} ({s['grade']})\n\n")
        for f in sorted(rows, key=lambda x: severity_rank(x["severity"])):
            buf.write(f"[{f['severity']}] {f['title']} ({f['confidence']})\n"
                      f"  {f['description']}\n  Evidence: {str(f.get('evidence'))[:400]}\n"
                      f"  Fix: {f['remediation']}\n\n")
        path = self._path("txt", self._slug(target["url"]))
        path.write_text(buf.getvalue(), encoding="utf-8")
        return path

    # ---- HTML ------------------------------------------------------------
    def html_report(self, scan_meta: dict, targets: list[dict],
                    findings_by_target: dict[str, list[dict]]) -> Path:
        all_rows = [f for rows in findings_by_target.values() for f in rows]
        s = self.mean_target_score(findings_by_target)
        template = Template(self.template_path.read_text(encoding="utf-8"))

        target_rows = "\n".join(
            f"<tr><td>{_esc(t['url'])}</td><td class='st st-{_esc(t.get('status'))}'>"
            f"{_esc(t.get('status'))}</td>"
            f"<td>{self.summarize(findings_by_target.get(t['url'], []))['score']}</td>"
            f"<td>{len(findings_by_target.get(t['url'], []))}</td></tr>"
            for t in targets)

        severity_rows = "\n".join(
            f"<tr><td><span class='sev sev-{k.lower()}'>{k}</span></td>"
            f"<td>{s['counts'][k]}</td></tr>" for k in SEVERITY_ORDER)

        sections = []
        for t in targets:
            rows = sorted(findings_by_target.get(t["url"], []),
                          key=lambda x: severity_rank(x["severity"]))
            ts = self.summarize(rows)
            cards = []
            if not rows:
                cards.append("<p class='clean'>No findings recorded for this target.</p>")
            for f in rows:
                cards.append(f"""
<article class="card sev-border-{_esc(f['severity'].lower())}">
  <header>
    <span class="sev sev-{_esc(f['severity'].lower())}">{_esc(f['severity'])}</span>
    <span class="fid">{_esc(f['finding_id'])}</span>
    <h4>{_esc(f['title'])}</h4>
  </header>
  <dl>
    <dt>Confidence</dt><dd>{_esc(f['confidence'])} <em>({_esc(f['verification_status'])})</em></dd>
    <dt>Category</dt><dd>{_esc(f['category'])}</dd>
    <dt>Detection</dt><dd>{_esc(f['detection_method'])}</dd>
    {f"<dt>Parameter</dt><dd><code>{_esc(f['parameter'])}</code></dd>" if f.get('parameter') else ""}
    {f"<dt>CWE</dt><dd>{_esc(f['cwe'])}</dd>" if f.get('cwe') else ""}
    {f"<dt>CVE</dt><dd>{_esc(f['cve'])}</dd>" if f.get('cve') else ""}
  </dl>
  <p class="desc">{_esc(f['description'])}</p>
  {f'<details><summary>Evidence</summary><pre>{_esc(_trim_evidence(f["evidence"]))}</pre></details>' if f.get('evidence') else ""}
  <p class="fix"><strong>Remediation:</strong> {_esc(f['remediation'])}</p>
</article>""")
            sections.append(f"""
<section class="target">
  <h3>{_esc(t['url'])}
    <span class="grade g-{ts['grade'].lower()}">{ts['score']} / {ts['grade']}</span></h3>
  <p class="meta">Status: {_esc(t.get('status'))} &middot; Requests: {t.get('request_count', 0)}
     &middot; Duration: {t.get('duration_s', 0)}s</p>
  {''.join(cards)}
</section>""")

        exec_summary = (
            f"{len(targets)} authorized target(s) were assessed with non-destructive checks. "
            f"{s['total']} finding(s) were recorded: "
            f"{s['counts']['CRITICAL']} critical, {s['counts']['HIGH']} high, "
            f"{s['counts']['MEDIUM']} medium, {s['counts']['LOW']} low, "
            f"{s['counts']['INFO']} informational. Overall score {s['score']}/100 "
            f"(grade {s['grade']}). "
            + ("Critical items should be triaged immediately."
               if s["counts"]["CRITICAL"] else
               "No critical items were identified by automated checks."))

        out = template.safe_substitute(
            generated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            scan_id=_esc(scan_meta.get("id")), note=_esc(scan_meta.get("note", "")),
            executive_summary=_esc(exec_summary),
            score=s["score"], grade=s["grade"],
            grade_class=f"g-{s['grade'].lower()}",
            severity_rows=severity_rows, target_rows=target_rows,
            total_findings=s["total"], target_count=len(targets),
            methodology=_esc(SCORE_METHOD).replace("\n", "<br>"),
            limitations="".join(f"<li>{_esc(x)}</li>" for x in LIMITATIONS),
            sections="".join(sections),
        )
        path = self._path("html", "combined")
        path.write_text(out, encoding="utf-8")
        return path

    def html_target(self, scan_meta: dict, target: dict, rows: list[dict]) -> Path:
        return self.html_report(scan_meta, [target], {target["url"]: rows})

    # ---- batch writer ----------------------------------------------------
    def write_target_reports(self, scan_meta: dict, target: dict, rows: list[dict]) -> dict:
        return {
            "json": str(self.json_target(target, rows)),
            "txt": str(self.txt_target(target, rows)),
            "html": str(self.html_target(scan_meta, target, rows)),
        }