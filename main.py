#!/usr/bin/env python3
"""TSMSS 2.0 Ultimate Edition entry point."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import json
from pathlib import Path
import signal
import sys

from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

import config as cfgmod
from config import KNOWN_MODULES, SEVERITY_ORDER, VALID_PROFILES
from core import termux_api as tap
from core.database import Database
from core.diagnostics import collect_device_diagnostics
from core.engine import MODULE_ORDER, TargetEngine, TargetScanResult, score
from core.evidence import EvidenceStore
from core.finding import Finding
from core.http_client import HttpClient
from core.logger import setup as setup_logging
from core.rate_limiter import RateLimiter
from core.report_manager import ReportManager, diff_scans
from core.scheduler import Scheduler
from core.scope import ScopeGuard
from core.validator import load_targets, validate
from core.verification import filter_by_baseline, load_baseline, save_baseline
from modules.dependency_audit import audit_local_dependencies
from modules.source_code import audit_source_directory
from paths import startup_probe
from ui import dashboard, menu
from ui.menu import console

RUNTIME = {
    "config": None,
    "db": None,
    "reports": None,
    "scope": None,
    "stop": None,
    "active_scan": None,
}


# ---------------------------------------------------------------- bootstrap
def bootstrap() -> None:
    RUNTIME["config"] = cfgmod.load()
    setup_logging(BASE / "logs", RUNTIME["config"].get("logging.level", "INFO"))
    RUNTIME["db"] = Database(BASE / "database" / "scans.db")
    RUNTIME["reports"] = ReportManager(BASE / "reports", BASE / "templates" / "report.html")
    RUNTIME["stop"] = asyncio.Event()


def build_scope(config) -> ScopeGuard:
    return ScopeGuard.from_config(config)


def make_http_factory(config, scope, limiter):
    def factory(stop_event, counter):
        return HttpClient(config, scope, limiter, stop_event, counter)
    return factory


def _rehydrate_findings(rows: list[dict]) -> list[Finding]:
    findings_objs: list[Finding] = []
    valid_fields = set(Finding.__dataclass_fields__.keys())
    for r in rows:
        data = {k: v for k, v in r.items() if k in valid_fields and v is not None}
        if " tags" in data or isinstance(data.get("tags"), str):
            try:
                data["tags"] = json.loads(data["tags"])
            except Exception:
                data["tags"] = []
        data["target"] = r.get("target") or r.get("target_url") or ""
        findings_objs.append(Finding(**data))
    return findings_objs


def render_diff_summary(diff_result: dict) -> None:
    totals = diff_result.get("totals", {})
    table = Table(
        "Target", "New", "Fixed", "Still Open",
        title=f"Scan Diff vs {Path(diff_result.get('previous_file', '')).name}",
    )
    for tgt, bucket in diff_result.get("targets", {}).items():
        table.add_row(
            tgt,
            f"[bright_red]{len(bucket.get('new', []))}[/bright_red]",
            f"[bright_green]{len(bucket.get('fixed', []))}[/bright_green]",
            f"[yellow]{len(bucket.get('still_open', []))}[/yellow]",
        )
    console.print(table)
    console.print(
        f"[bold]Diff Totals:[/bold] new={totals.get('new', 0)}  "
        f"fixed={totals.get('fixed', 0)}  still-open={totals.get('still_open', 0)}"
    )


# ------------------------------------------------------------------- scan
async def run_scan(
    urls: list[str] | None = None,
    note: str = "",
    auto_reports: bool = False,
    *,
    resume_scan_id: str | None = None,
    baseline_path: str | Path | None = None,
    write_baseline_path: str | Path | None = None,
    diff_path: str | Path | None = None,
    only_modules: list[str] | None = None,
) -> str | None:
    config = RUNTIME["config"]
    db: Database = RUNTIME["db"]

    baseline_fps: set[tuple[str, str, str, str]] = set()
    if baseline_path:
        baseline_fps = load_baseline(baseline_path)

    if resume_scan_id:
        scan_row = db.scan(resume_scan_id)
        if not scan_row:
            console.print(f"[red]Unknown scan ID to resume: {resume_scan_id}[/red]")
            return None
        pending_urls = db.unfinished_target_urls(resume_scan_id)
        all_target_rows = db.targets(resume_scan_id)
        all_urls = [r["url"] for r in all_target_rows]
        scope = build_scope(config)
        for u in all_urls:
            scope.register(u)
        RUNTIME["scope"] = scope
        admitted = pending_urls
        scan_id = resume_scan_id
        db.reopen_scan(scan_id)
        db.audit(scan_id, "scan_resume", f"{len(admitted)} unfinished targets")
    else:
        urls = list(urls or [])
        if not urls:
            console.print("[yellow]No valid targets.[/yellow]")
            return None
        limit = int(config.get("scope.max_targets", 500))
        if len(urls) > limit:
            console.print(f"[yellow]Trimming {len(urls)} targets to {limit}.[/yellow]")
            urls = urls[:limit]

        scope = build_scope(config)
        for u in urls:
            scope.register(u)
        RUNTIME["scope"] = scope

        admitted = []
        blocked: list[tuple[str, str]] = []
        for u in urls:
            decision = scope.check_target(u)
            if decision.allowed:
                admitted.append(u)
            else:
                blocked.append((u, decision.reason))
        for u, reason in blocked:
            console.print(f"[yellow]skip[/yellow] {u} [grey50]({reason})[/grey50]")
        if not admitted:
            console.print("[red]Nothing in scope.[/red]")
            return None

        scan_id = db.create_scan(config.data, len(admitted), note, tap.environment_report())
        db.add_targets(scan_id, admitted)
        db.audit(scan_id, "scan_start", f"{len(admitted)} targets")

    RUNTIME["active_scan"] = scan_id
    await tap.wake_lock(True)
    stop_event: asyncio.Event = RUNTIME["stop"]
    stop_event.clear()

    snap = config.snapshot()
    if only_modules:
        disabled = [m for m in MODULE_ORDER if m not in set(only_modules)]
        config.set("modules.disabled", disabled)

    try:
        limiter = RateLimiter(
            config.get("scan.max_requests_per_second", 4.0),
            config.get("scan.per_host_requests_per_second", 1.5),
        )
        reports_base = RUNTIME["reports"].base if RUNTIME.get("reports") is not None else (BASE / "reports")
        evidence = EvidenceStore(
            reports_base / scan_id / "evidence",
            int(config.get("reporting.evidence_max_bytes", 8192)),
        )
        engine = TargetEngine(
            config,
            cfgmod.load_rules(),
            scope,
            make_http_factory(config, scope, limiter),
            evidence,
        )
        counters: Counter = Counter()
        suppressed_total = 0

        async def worker(url: str) -> TargetScanResult:
            nonlocal suppressed_total
            db.set_target_status(scan_id, url, "running")
            result = await engine.scan(url, stop_event)
            if baseline_fps and result.findings:
                kept, supp = filter_by_baseline(result.findings, baseline_fps)
                suppressed_total += supp
                result.findings = kept
                result.score, result.grade = score(result.findings)
            for f in result.findings:
                counters[f.severity] += 1
            if result.findings and config.get("reporting.include_response_bodies", True):
                for f in result.findings:
                    if f.evidence:
                        evidence.save(f.finding_id, f.evidence)
            db.add_findings(scan_id, result.findings)
            return result

        async def on_done(url: str, result: TargetScanResult) -> None:
            status = "done" if result.ok else "failed"
            db.set_target_status(
                scan_id,
                url,
                status,
                error=None if result.ok else (result.error or "scan failed"),
                score=result.score,
                requests=result.requests,
            )
            db.save_checkpoint(scan_id, {"last_url": url, "completed": True})
            db.audit(scan_id, "target_done", f"{url} status={status} score={result.score}")

        scheduler = Scheduler(config, stop_event, on_done)

        if admitted:
            with Live(
                dashboard.render(scheduler.state, counters, scan_id),
                console=console,
                refresh_per_second=3,
                transient=False,
            ) as live:
                task = asyncio.create_task(scheduler.run(admitted, worker))
                while not task.done():
                    await asyncio.sleep(0.4)
                    live.update(dashboard.render(scheduler.state, counters, scan_id))
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                live.update(dashboard.render(scheduler.state, counters, scan_id))

        if admitted and scheduler.state.completed == 0 and scheduler.state.failed > 0:
            console.print("[yellow]every target failed - check network and scope[/yellow]")

        status = "interrupted" if stop_event.is_set() else "complete"
        db.finish_scan(scan_id, status)
        db.audit(scan_id, "scan_end", status)
        await tap.wake_lock(False)

        rows = [dict(r) for r in db.findings(scan_id)]
        findings_objs = _rehydrate_findings(rows)
        overall, grade = score(findings_objs)
        all_counts = Counter(f.severity for f in findings_objs)

        if write_baseline_path:
            bpath = save_baseline(write_baseline_path, findings_objs)
            console.print(f"[bright_cyan]Baseline written:[/bright_cyan] {bpath}")

        if diff_path:
            _, _, by_target = _load_scan_rows(scan_id)
            if by_target is not None:
                diff_res = diff_scans(by_target, diff_path)
                render_diff_summary(diff_res)

        supp_msg = f"  Suppressed(baseline) {suppressed_total}" if baseline_fps else ""
        console.print(Panel(
            f"Scan [bold bright_cyan]{scan_id}[/bold bright_cyan] {status}\n"
            f"Completed {scheduler.state.completed}  Failed {scheduler.state.failed}  "
            f"Skipped {scheduler.state.skipped}{supp_msg}\n"
            f"Findings: {menu.severity_bar(dict(all_counts))}\n"
            f"Score {overall}/100 (grade {grade})  Duration {scheduler.state.elapsed}s",
            border_style="bright_cyan" if status == "complete" else "yellow",
        ))
        if auto_reports:
            written = generate_reports(scan_id)
            db.save_report_paths(scan_id, written)
            for fmt, path in written.items():
                console.print(f"[bright_cyan]{fmt.upper()} report:[/bright_cyan] {path}")
        else:
            console.print(f"[grey62]Reports: {reports_base}[/grey62]")

        if config.get("safety.notify_on_complete", True):
            await tap.notify(
                "TSMSS scan finished",
                f"{status}: {scheduler.state.completed} done, {len(rows)} findings",
            )
        await tap.vibrate()
        return scan_id
    finally:
        if only_modules:
            config.restore(snap)
        RUNTIME["active_scan"] = None


# --------------------------------------------------------------- handlers
def handle_single() -> None:
    raw = menu.ask("Target URL")
    res = validate(raw)
    if not res.valid:
        console.print(f"[red]Invalid:[/red] {res.reason}")
        return
    if not menu.confirm_authorization():
        console.print("[yellow]Authorization not confirmed; aborting.[/yellow]")
        return
    asyncio.run(run_scan([res.normalized], "single", auto_reports=True))


def handle_multi() -> None:
    console.print("[grey62]Paste one URL per line, blank line to finish.[/grey62]")
    urls, seen = [], set()
    while True:
        line = Prompt.ask("url", default="", show_default=False)
        if not line.strip():
            break
        res = validate(line)
        if not res.valid:
            console.print(f"  [red]{res.reason}[/red]")
            continue
        if res.normalized.lower() in seen:
            console.print("  [yellow]duplicate[/yellow]")
            continue
        seen.add(res.normalized.lower())
        urls.append(res.normalized)
    if urls and menu.confirm_authorization():
        asyncio.run(run_scan(urls, "multi", auto_reports=True))


def handle_file() -> None:
    path = menu.ask("TXT file path (or 'paste' to enter URLs manually)", "targets.txt")
    if path.strip().lower() == "paste":
        handle_multi()
        return
    try:
        urls, rejected = load_targets(path)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return
    console.print(f"[green]{len(urls)} valid[/green], [yellow]{len(rejected)} rejected[/yellow]")
    if rejected:
        table = Table("line", "value", "reason", show_lines=False)
        for r in rejected[:15]:
            table.add_row(str(r["line"]), r["raw"][:50], r["reason"])
        console.print(table)
    if not urls:
        return
    prof = menu.ask("Scan profile (quick / standard / passive / deep)", "standard").strip().lower()
    snap = RUNTIME["config"].snapshot()
    try:
        if prof in VALID_PROFILES:
            RUNTIME["config"].apply_profile(prof)
        if not menu.confirm_authorization():
            return
        asyncio.run(run_scan(urls, f"file:{path}", auto_reports=True))
    finally:
        RUNTIME["config"].restore(snap)


def handle_focused_scan(modules_list: list[str], label: str) -> None:
    raw = menu.ask("Target URL (or path to targets.txt)", "targets.txt")
    if Path(raw).is_file():
        urls, _ = load_targets(raw)
    else:
        res = validate(raw)
        if not res.valid:
            console.print(f"[red]Invalid:[/red] {res.reason}")
            return
        urls = [res.normalized]
    if not urls:
        console.print("[yellow]No valid targets.[/yellow]")
        return
    if not menu.confirm_authorization():
        return
    asyncio.run(run_scan(urls, f"module:{label}", auto_reports=True, only_modules=modules_list))


def handle_source_code_audit() -> None:
    path_str = menu.ask("Local repository or source directory path", ".")
    p = Path(path_str)
    if not p.exists():
        console.print(f"[red]Path does not exist:[/red] {p}")
        return
    findings = audit_source_directory(p)
    _persist_and_display_local_audit(findings, f"source://{p.resolve().name}", "source-code-audit")


def handle_dependency_audit() -> None:
    raw = menu.ask("Local project directory/manifest path OR Target URL", ".")
    if raw.startswith(("http://", "https://")):
        res = validate(raw)
        if not res.valid:
            console.print(f"[red]Invalid URL:[/red] {res.reason}")
            return
        if menu.confirm_authorization():
            asyncio.run(run_scan([res.normalized], "dependency-audit", auto_reports=True, only_modules=["dependency_audit"]))
        return
    p = Path(raw)
    if not p.exists():
        console.print(f"[red]Path does not exist:[/red] {p}")
        return
    findings = audit_local_dependencies(p)
    _persist_and_display_local_audit(findings, f"deps://{p.resolve().name}", "dependency-audit")


def _persist_and_display_local_audit(findings: list[Finding], target_label: str, note: str) -> None:
    db: Database = RUNTIME["db"]
    cfg = RUNTIME["config"]
    scan_id = db.create_scan(cfg.data, 1, note, tap.environment_report())
    db.add_targets(scan_id, [target_label])
    val, grade = score(findings)
    db.add_findings(scan_id, findings)
    db.set_target_status(scan_id, target_label, "done", score=val, requests=0)
    db.finish_scan(scan_id, "complete")
    counts = Counter(f.severity for f in findings)
    console.print(Panel(
        f"Local Audit [bold bright_cyan]{scan_id}[/bold bright_cyan] complete\n"
        f"Target: [cyan]{target_label}[/cyan]\n"
        f"Findings ({len(findings)}): {menu.severity_bar(dict(counts))}\n"
        f"Score: {val}/100 (Grade {grade})",
        border_style="bright_cyan",
    ))
    for f in findings[:25]:
        console.print(f"  [{f.severity}] {f.title} — [grey62]{f.evidence}[/grey62]")
    written = generate_reports(scan_id)
    db.save_report_paths(scan_id, written)
    for fmt, path in written.items():
        console.print(f"[bright_cyan]{fmt.upper()} report:[/bright_cyan] {path}")


SETTINGS_KEYS: tuple[str, ...] = (
    "scan.concurrency_targets", "scan.max_requests_per_second",
    "scan.per_host_requests_per_second", "scan.request_timeout",
    "scan.batch_size", "scan.delay_between_requests",
    "scope.allow_private_targets", "scope.allow_subdomains",
    "scope.include_patterns", "scope.exclude_patterns",
    "scope.max_targets", "safety.max_total_requests_per_target",
    "active.safe_mode", "active.xss", "active.sqli", "active.ssti", "active.xxe",
    "infra.enable_nmap", "safety.check_battery",
    "modules.disabled",
    "tools.mode", "tools.max_runtime", "tools.rate_limit",
    "tools.allow_root_tools", "tools.enabled", "tools.disabled",
)


def _parse_list_setting(raw: str) -> list[str]:
    text = (raw or "").strip()
    if not text or text.lower() in ("none", "[]"):
        return []
    if text.startswith("["):
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    return [part.strip() for part in text.split(",") if part.strip()]


def handle_settings() -> None:
    config = RUNTIME["config"]
    snapshot = config.snapshot()
    while True:
        table = Table("key", "value", title="Current settings", show_header=True)
        for key in SETTINGS_KEYS:
            table.add_row(key, str(config.get(key)))
        console.print(table)
        key = Prompt.ask("Key to change (blank to save+exit, 'rollback' to discard)",
                         default="", show_default=False).strip()
        if key.lower() in ("rollback", "cancel", "abort"):
            config.restore(snapshot)
            console.print("[yellow]Changes discarded; rolled back to previous settings.[/yellow]")
            return
        if not key:
            errs = config.validate()
            if errs:
                for e in errs:
                    console.print(f"[red]{e}[/red]")
                if Confirm.ask("Discard invalid changes and rollback?", default=True):
                    config.restore(snapshot)
                    console.print("[yellow]Rolled back invalid changes.[/yellow]")
                    return
                continue
            config.save()
            console.print("[green]Saved.[/green]")
            return
        if config.get(key) is None:
            console.print("[red]Unknown key.[/red]")
            continue
        current = config.get(key)
        if isinstance(current, bool):
            config.set(key, Confirm.ask(key, default=current))
        elif isinstance(current, int):
            config.set(key, IntPrompt.ask(key, default=current))
        elif isinstance(current, float):
            raw = Prompt.ask(key, default=str(current))
            try:
                config.set(key, float(raw))
            except ValueError:
                console.print("[red]Invalid number.[/red]")
        elif isinstance(current, list):
            default_str = ", ".join(str(x) for x in current)
            raw = Prompt.ask(f"{key} (comma-separated or JSON list)", default=default_str)
            try:
                config.set(key, _parse_list_setting(raw))
            except json.JSONDecodeError:
                console.print("[red]Invalid list format.[/red]")
        else:
            raw = Prompt.ask(key, default=str(current))
            try:
                config.set(key, json.loads(raw))
            except json.JSONDecodeError:
                config.set(key, raw)


def handle_previous() -> None:
    db: Database = RUNTIME["db"]
    rows = db.recent_scans(20)
    if not rows:
        console.print("[grey62]No scans yet.[/grey62]")
        return
    table = Table("ID", "Started", "Status", "Targets", "Note", title="Scan History")
    for r in rows:
        table.add_row(r["id"], r["started_at"], r["status"], str(r["total_targets"]),
                      (r["note"] or "")[:30])
    console.print(table)
    act = menu.ask("Action (blank=back, 'resume', 'report', 'diff')", "").strip().lower()
    if act == "resume":
        handle_resume()
    elif act == "report":
        fmt = menu.ask("Format (all/html/json/jsonl/md/txt/csv/sarif/ai)", "all").strip().lower()
        handle_report(fmt)
    elif act == "diff":
        scan_id = menu.ask("Current Scan ID", rows[0]["id"])
        prev_file = menu.ask("Previous JSON report path")
        meta, _, by_target = _load_scan_rows(scan_id)
        if meta and prev_file:
            render_diff_summary(diff_scans(by_target, prev_file))


def handle_findings() -> None:
    db: Database = RUNTIME["db"]
    recent = db.recent_scans(1)
    default_id = recent[0]["id"] if recent else ""
    scan_id = menu.ask("Scan ID (or 'all')", default_id)
    sev_filter = menu.ask("Filter by severity (blank=ALL, CRITICAL/HIGH/MEDIUM/LOW/INFO)", "").strip().upper()
    vstat_filter = menu.ask(
        "Filter by verification (blank=ALL, CONFIRMED/STRONG EVIDENCE/POTENTIAL/NEEDS MANUAL VERIFICATION)",
        "",
    ).strip().upper()
    rows = db.search_findings(
        scan_id=None if scan_id in ("", "all") else scan_id,
        severity=sev_filter or None,
        verification_status=vstat_filter or None,
    )
    if not rows:
        console.print("[grey62]No matching findings.[/grey62]")
        return
    for r in rows[:40]:
        colour = {"CRITICAL": "bright_red", "HIGH": "dark_orange", "MEDIUM": "yellow",
                  "LOW": "bright_cyan", "INFO": "grey62"}.get(r["severity"], "white")
        console.print(Panel(
            f"[{colour} bold]{r['severity']}[/{colour} bold] [grey50]{r['finding_id']}[/grey50] "
            f"[cyan]({r['verification_status']} / {r['confidence']})[/cyan]\n"
            f"[bold]{r['title']}[/bold]\n"
            f"[grey62]{r['target_url']}[/grey62]  {r['owasp_reference'] or ''}\n\n"
            f"{r['description']}\n\n"
            f"[grey50]evidence:[/grey50] {(r['evidence'] or '')[:350]}\n"
            f"[bright_cyan]fix:[/bright_cyan] {r['remediation']}",
            border_style=colour,
        ))


def _load_scan_rows(scan_id: str):
    db = RUNTIME["db"]
    if not db.scan(scan_id):
        console.print("[red]Unknown scan ID.[/red]")
        return None, None, None
    meta = {"id": scan_id, "note": db.scan(scan_id)["note"] or ""}
    targets = [dict(t) for t in db.targets(scan_id)]
    by_target: dict[str, list] = {t["url"]: [] for t in targets}
    for r in db.findings(scan_id):
        by_target.setdefault(r["target_url"], []).append(dict(r))
    return meta, targets, by_target


def generate_reports(scan_id: str) -> dict[str, str]:
    """Render every format for a finished scan and return the written paths."""
    meta, targets, by_target = _load_scan_rows(scan_id)
    if meta is None:
        return {}
    all_rows = [f for rows in by_target.values() for f in rows]
    reports: ReportManager = RUNTIME["reports"]
    return {
        "html": str(reports.html_report(meta, targets, by_target)),
        "json": str(reports.json_report(meta, targets, by_target)),
        "jsonl": str(reports.jsonl_report(meta, targets, by_target)),
        "md": str(reports.markdown_report(meta, targets, by_target)),
        "txt": str(reports.txt_report(meta, targets, by_target)),
        "csv": str(reports.csv_report(all_rows)),
        "sarif": str(reports.sarif_report(meta, targets, by_target)),
    }


def handle_ai_report() -> None:
    db: Database = RUNTIME["db"]
    recent = db.recent_scans(1)
    default_id = recent[0]["id"] if recent else ""
    scan_id = menu.ask("Scan ID for AI Report Package", default_id)
    meta, targets, by_target = _load_scan_rows(scan_id)
    if meta is None:
        return
    pkg = RUNTIME["reports"].ai_package_report(meta, targets, by_target)
    errs = pkg.get("validation_errors", [])
    console.print(Panel(
        f"[bold bright_cyan]Manual AI Upload Package Created[/bold bright_cyan]\n"
        f"Directory : {pkg['package_dir']}\n"
        f"JSON      : {pkg['json']}\n"
        f"JSONL     : {pkg['jsonl']}\n"
        f"Prompt    : {pkg['prompt']}\n"
        f"Chunks    : {len(pkg['chunks'])} file(s)\n"
        f"Schema    : {'VALID (0 errors)' if not errs else f'{len(errs)} error(s)'}",
        border_style="bright_cyan",
    ))


def handle_report(fmt: str = "all") -> None:
    db: Database = RUNTIME["db"]
    recent = db.recent_scans(1)
    default_id = recent[0]["id"] if recent else ""
    scan_id = menu.ask("Scan ID", default_id)
    meta, targets, by_target = _load_scan_rows(scan_id)
    if meta is None:
        return
    if fmt == "all":
        for k, p in generate_reports(scan_id).items():
            console.print(f"[green]{k.upper()}:[/green] {p}")
        return
    if fmt == "ai":
        pkg = RUNTIME["reports"].ai_package_report(meta, targets, by_target)
        console.print(f"[green]AI Package:[/green] {pkg['package_dir']}")
        return
    all_rows = [f for v in by_target.values() for f in v]
    reports: ReportManager = RUNTIME["reports"]
    if fmt == "json":
        path = reports.json_report(meta, targets, by_target)
    elif fmt == "jsonl":
        path = reports.jsonl_report(meta, targets, by_target)
    elif fmt == "md":
        path = reports.markdown_report(meta, targets, by_target)
    elif fmt == "txt":
        path = reports.txt_report(meta, targets, by_target)
    elif fmt == "csv":
        path = reports.csv_report(all_rows)
    elif fmt == "sarif":
        path = reports.sarif_report(meta, targets, by_target)
    else:
        path = reports.html_report(meta, targets, by_target)
    console.print(f"[green]Written:[/green] {path}")
    if asyncio.run(tap.clipboard(str(path))):
        console.print("[grey62]Path copied to clipboard.[/grey62]")


def handle_tools() -> None:
    env = tap.environment_report()
    table = Table("Tool", "Status", title="External & Optional Tools")
    for tool, present in env.items():
        table.add_row(tool, "[bright_green]installed[/bright_green]" if present else "[grey50]missing (uses Python fallback)[/grey50]")
    console.print(table)
    console.print("[grey62]Run 'bash tools.sh -s' to inspect or 'bash tools.sh' to install optional tools.[/grey62]")


def handle_diagnostics() -> None:
    diag = collect_device_diagnostics(BASE)
    env = diag["environment"]
    mem = diag["memory"]
    disk = diag["storage"]
    console.print(Panel(
        f"[bold bright_cyan]Local Device & Termux Diagnostics[/bold bright_cyan] (Isolated from Website Scans)\n"
        f"OS / Release : {env['android_release']} (SDK: {env['android_sdk'] or 'n/a'})\n"
        f"Termux       : {env['termux_version']}  |  Root: {'Yes' if env['is_root'] else 'No (Non-Root First)'}\n"
        f"Architecture : {env['cpu_arch']} ({env['cpu_cores']} cores)  |  Python: {env['python_version']}\n"
        f"Memory (RAM) : {mem['available_mb']} MB available / {mem['total_mb']} MB total\n"
        f"Storage      : {disk['free_mb']} MB free / {disk['total_mb']} MB total",
        border_style="bright_cyan",
    ))
    mat_table = Table("Feature / Capability", "Status", "Notes", title="Android / Termux Compatibility Matrix")
    for item in diag["compatibility_matrix"]:
        st = item["status"]
        col = "bright_green" if st == "SUPPORTED" else "yellow" if st == "PARTIALLY SUPPORTED" else "cyan" if st == "REQUIRES TESTING" else "bright_red"
        mat_table.add_row(item["feature"], f"[{col}]{st}[/{col}]", item["note"])
    console.print(mat_table)
    if diag["warnings"]:
        console.print("[bold yellow]Compatibility Warnings & Recommendations:[/bold yellow]")
        for w in diag["warnings"]:
            console.print(f"  - {w}")


def handle_env() -> None:
    handle_diagnostics()


def handle_resume() -> None:
    rows = RUNTIME["db"].resumable_scans()
    if not rows:
        console.print("[grey62]Nothing to resume.[/grey62]")
        return
    for r in rows:
        counts = RUNTIME["db"].counts(r["id"])
        console.print(f"{r['id']}  {r['started_at']}  {r['status']}  counts={counts}")
    scan_id = menu.ask("Scan ID to resume", rows[0]["id"])
    pending = RUNTIME["db"].unfinished_target_urls(scan_id)
    if not pending:
        console.print("[yellow]No unfinished targets for this scan.[/yellow]")
        return
    console.print(f"[yellow]{len(pending)} target(s) outstanding.[/yellow]")
    if menu.confirm_authorization():
        asyncio.run(run_scan(resume_scan_id=scan_id, auto_reports=True))


def handle_stop() -> None:
    if RUNTIME["active_scan"]:
        RUNTIME["stop"].set()
        console.print("[yellow]Stop signalled; finishing in-flight requests.[/yellow]")
    else:
        console.print("[grey62]No active scan.[/grey62]")


HANDLERS = {
    "1": handle_single,
    "2": handle_file,
    "3": lambda: handle_focused_scan(["reconnaissance", "dns_security", "information_disclosure"], "recon"),
    "4": lambda: handle_focused_scan(["http_security", "cookies", "cors"], "http"),
    "5": lambda: handle_focused_scan(["ssl_tls"], "tls"),
    "6": lambda: handle_focused_scan(["dns_security"], "dns"),
    "7": lambda: handle_focused_scan(["api_security", "cors", "authentication", "authorization"], "api"),
    "8": handle_source_code_audit,
    "9": handle_dependency_audit,
    "10": handle_findings,
    "11": handle_ai_report,
    "12": handle_previous,
    "13": handle_tools,
    "14": handle_diagnostics,
    "15": handle_settings,
}


# ------------------------------------------------------------------- cli
def _print_rejections(rejected: list[dict]) -> None:
    if not rejected:
        return
    table = Table("line", "value", "reason")
    for r in rejected[:15]:
        table.add_row(str(r["line"]), r["raw"][:50], r["reason"])
    console.print(table)
    if len(rejected) > 15:
        console.print(f"[grey62]... and {len(rejected) - 15} more[/grey62]")


def db_scans() -> list[list[str]]:
    """Severity lists of every finding in the most recent scan."""
    db = RUNTIME["db"]
    rows = db.recent_scans(1)
    if not rows:
        return []
    return [[r["severity"] for r in db.findings(rows[0]["id"])]]


def _ensure_bootstrap() -> None:
    if RUNTIME.get("config") is None or RUNTIME.get("db") is None or RUNTIME.get("reports") is None:
        bootstrap()


def _add_scan_flags(parser: argparse.ArgumentParser, is_subcommand: bool = False) -> None:
    if is_subcommand:
        parser.add_argument("targets", nargs="*", help="target file path or URL(s)")
        parser.add_argument("-d", "--dry-run", nargs="?", const=True, default=None, metavar="FILE",
                            help="validate targets without scanning")
    else:
        parser.add_argument("-l", "--list", metavar="FILE", help="validate and print FILE, then exit")
        parser.add_argument("-d", "--dry-run", metavar="FILE", help="validate FILE without scanning")
    parser.add_argument("-b", "--batch", metavar="FILE", help="scan every URL in FILE, then exit")
    parser.add_argument("-y", "--yes", action="store_true", help="skip the authorization prompt")
    parser.add_argument("--no-reports", action="store_true", help="skip report generation")
    parser.add_argument("--profile", default="", choices=["", *VALID_PROFILES],
                        help="scan preset overriding rate, timeouts, module set and concurrency")
    parser.add_argument("--baseline", metavar="FILE", default="",
                        help="suppress findings matching exact fingerprint in baseline FILE")
    parser.add_argument("--write-baseline", metavar="FILE", default="",
                        help="write scan findings as a baseline JSON file")
    parser.add_argument("--diff", metavar="FILE", default="",
                        help="compare current scan against previous JSON report or baseline FILE")
    parser.add_argument("--resume", metavar="SCAN_ID", default="",
                        help="resume unfinished targets of an interrupted scan ID in-place")
    parser.add_argument("--source-dir", metavar="DIR", default="",
                        help="audit a local source code directory and its dependency manifests")
    parser.add_argument("--plain-ui", action="store_true",
                        help="use plain terminal output without Rich panels")
    parser.add_argument("--no-soft404", action="store_true",
                        help="disable per-host soft-404 calibration and downgrade")
    parser.add_argument("--min-confidence", default="",
                        choices=["", "CONFIRMED", "STRONG EVIDENCE", "HIGH CONFIDENCE",
                                 "POTENTIAL", "MEDIUM CONFIDENCE", "LOW CONFIDENCE"],
                        help="drop findings below this confidence")
    parser.add_argument("--fail-on", default="", choices=["", "CRITICAL", "HIGH", "MEDIUM"],
                        help="exit 2 when a finding at or above this severity exists")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="main.py",
        description="TSMSS 2.0 Ultimate Edition — Authorized Mobile Security Auditing & Bug Bounty Platform.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with no arguments for the 16-option interactive mobile menu.",
    )
    _add_scan_flags(ap, is_subcommand=False)

    sub = ap.add_subparsers(dest="subcommand")

    p_scan = sub.add_parser("scan", help="run a scan against a target file or URL(s)")
    _add_scan_flags(p_scan, is_subcommand=True)

    p_list = sub.add_parser("list", help="validate and list targets from a file")
    p_list.add_argument("file", nargs="?", default="", help="target file path")
    p_list.add_argument("-l", "--list", dest="list_file", metavar="FILE", help="target file path")

    p_report = sub.add_parser("report", help="generate or diff reports for a scan ID")
    p_report.add_argument("scan_id", nargs="?", default="latest",
                          help="scan ID (defaults to 'latest')")
    p_report.add_argument("-f", "--format", default="all",
                          choices=["html", "json", "jsonl", "md", "txt", "csv", "sarif", "ai", "all"],
                          help="report format to write")
    p_report.add_argument("--diff", metavar="FILE", default="",
                          help="diff this scan against a previous JSON report")

    p_config = sub.add_parser("config", help="inspect, validate or update settings")
    p_config.add_argument("--show", action="store_true", help="print current settings")
    p_config.add_argument("--validate", action="store_true", help="validate current settings")
    p_config.add_argument("--get", metavar="KEY", help="print a single setting value")
    p_config.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                          help="update a setting and save if valid")
    return ap


def _load_cli_targets(source: str | list[str]) -> tuple[list[str], list[dict], str] | None:
    if isinstance(source, list):
        if len(source) == 1 and Path(source[0]).exists():
            source = source[0]
        else:
            urls, rejected, seen = [], [], set()
            for idx, raw in enumerate(source, 1):
                res = validate(raw)
                if not res.valid:
                    rejected.append({"line": idx, "raw": raw, "reason": res.reason})
                elif res.normalized.lower() in seen:
                    rejected.append({"line": idx, "raw": raw, "reason": "duplicate"})
                else:
                    seen.add(res.normalized.lower())
                    urls.append(res.normalized)
            return urls, rejected, "cli"
    try:
        urls, rejected = load_targets(source)
        return urls, rejected, str(source)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return None


def _cmd_list(source: str) -> int:
    _ensure_bootstrap()
    loaded = _load_cli_targets(source)
    if loaded is None:
        return 1
    urls, rejected, _ = loaded
    _print_rejections(rejected)
    if not urls:
        console.print("[red]No valid targets.[/red]")
        return 1
    for i, u in enumerate(urls, 1):
        console.print(f"{i:>3}. {u}")
    console.print(f"[grey62]{len(urls)} valid, {len(rejected)} rejected[/grey62]")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    _ensure_bootstrap()
    if getattr(args, "plain_ui", False):
        menu.set_plain_ui(True)

    config = RUNTIME["config"]
    snap = config.snapshot()
    try:
        if getattr(args, "profile", ""):
            config.apply_profile(args.profile)
        if getattr(args, "min_confidence", ""):
            config.set("scan.min_confidence", args.min_confidence)
        if getattr(args, "no_soft404", False):
            config.set("scan.no_soft404", True)

        # Handle local --source-dir mode
        src_dir = getattr(args, "source_dir", "")
        if src_dir:
            p = Path(src_dir)
            if not p.exists():
                console.print(f"[red]Source directory not found: {p}[/red]")
                return 1
            findings = audit_source_directory(p) + audit_local_dependencies(p)
            if getattr(args, "baseline", ""):
                findings, _ = filter_by_baseline(findings, load_baseline(args.baseline))
            if getattr(args, "write_baseline", ""):
                save_baseline(args.write_baseline, findings)
            _persist_and_display_local_audit(findings, f"source://{p.resolve().name}", f"source:{p.name}")
            return 0

        # Handle --resume <scan_id>
        resume_id = getattr(args, "resume", "")
        if resume_id:
            if not args.yes and not menu.confirm_authorization():
                console.print("[yellow]Authorization not confirmed.[/yellow]")
                return 1
            res_scan = asyncio.run(run_scan(
                resume_scan_id=resume_id,
                auto_reports=not args.no_reports,
                baseline_path=getattr(args, "baseline", "") or None,
                write_baseline_path=getattr(args, "write_baseline", "") or None,
                diff_path=getattr(args, "diff", "") or None,
            ))
            return 0 if res_scan else 1

        dry_run_arg = getattr(args, "dry_run", None)
        targets_pos = getattr(args, "targets", None) or []
        source: str | list[str] | None = None
        if isinstance(dry_run_arg, str) and dry_run_arg:
            source = dry_run_arg
        elif args.batch:
            source = args.batch
        elif targets_pos:
            source = targets_pos
        if not source:
            console.print("[red]No target source specified.[/red]")
            return 1

        loaded = _load_cli_targets(source)
        if loaded is None:
            return 1
        urls, rejected, label = loaded
        _print_rejections(rejected)
        if not urls:
            console.print("[red]No valid targets.[/red]")
            return 1

        if dry_run_arg:
            console.print(f"[green]{len(urls)} valid[/green], [yellow]{len(rejected)} rejected[/yellow]")
            return 0

        console.print(f"[bold]{len(urls)}[/bold] target(s) from [cyan]{label}[/cyan]")
        if not args.yes and not menu.confirm_authorization():
            console.print("[yellow]Authorization not confirmed.[/yellow]")
            return 1

        asyncio.run(run_scan(
            urls,
            f"batch:{label}",
            auto_reports=not args.no_reports,
            baseline_path=getattr(args, "baseline", "") or None,
            write_baseline_path=getattr(args, "write_baseline", "") or None,
            diff_path=getattr(args, "diff", "") or None,
        ))
        if args.fail_on:
            limit = SEVERITY_ORDER.index(args.fail_on)
            hits = [f for s in db_scans() for f in s if SEVERITY_ORDER.index(f) <= limit]
            if hits:
                console.print(f"[red]fail-on {args.fail_on}: {len(hits)} finding(s)[/red]")
                return 2
        return 0
    finally:
        config.restore(snap)


def _cmd_report(args: argparse.Namespace) -> int:
    _ensure_bootstrap()
    db: Database = RUNTIME["db"]
    scan_id = args.scan_id
    if not scan_id or scan_id == "latest":
        recent = db.recent_scans(1)
        if not recent:
            console.print("[red]No scans in database.[/red]")
            return 1
        scan_id = recent[0]["id"]
    meta, targets, by_target = _load_scan_rows(scan_id)
    if meta is None:
        return 1

    if getattr(args, "diff", ""):
        diff_res = diff_scans(by_target, args.diff)
        render_diff_summary(diff_res)

    fmt = args.format
    if fmt == "all":
        written = generate_reports(scan_id)
    elif fmt == "ai":
        pkg = RUNTIME["reports"].ai_package_report(meta, targets, by_target)
        written = {"ai_package": str(pkg["package_dir"]), "json": str(pkg["json"]), "prompt": str(pkg["prompt"])}
    else:
        all_rows = [f for v in by_target.values() for f in v]
        reports: ReportManager = RUNTIME["reports"]
        if fmt == "json":
            written = {"json": str(reports.json_report(meta, targets, by_target))}
        elif fmt == "jsonl":
            written = {"jsonl": str(reports.jsonl_report(meta, targets, by_target))}
        elif fmt == "md":
            written = {"md": str(reports.markdown_report(meta, targets, by_target))}
        elif fmt == "txt":
            written = {"txt": str(reports.txt_report(meta, targets, by_target))}
        elif fmt == "csv":
            written = {"csv": str(reports.csv_report(all_rows))}
        elif fmt == "sarif":
            written = {"sarif": str(reports.sarif_report(meta, targets, by_target))}
        else:
            written = {"html": str(reports.html_report(meta, targets, by_target))}
    db.save_report_paths(scan_id, written)
    for k, path in written.items():
        console.print(f"[green]{k.upper()} report:[/green] {path}")
    return 0


def _coerce_setting_value(current, raw_val: str):
    if isinstance(current, bool):
        if raw_val.lower() in ("true", "1", "yes", "on"):
            return True
        if raw_val.lower() in ("false", "0", "no", "off"):
            return False
        raise ValueError(f"expected boolean, got {raw_val!r}")
    if isinstance(current, int):
        return int(raw_val)
    if isinstance(current, float):
        return float(raw_val)
    if isinstance(current, list):
        return _parse_list_setting(raw_val)
    try:
        return json.loads(raw_val)
    except json.JSONDecodeError:
        return raw_val


def _cmd_config(args: argparse.Namespace) -> int:
    _ensure_bootstrap()
    config = RUNTIME["config"]
    snapshot = config.snapshot()

    if args.set:
        for pair in args.set:
            if "=" not in pair:
                console.print(f"[red]Invalid --set {pair!r}; expected KEY=VALUE[/red]")
                config.restore(snapshot)
                return 1
            key, raw_val = pair.split("=", 1)
            key = key.strip()
            current = config.get(key)
            if current is None:
                console.print(f"[red]Unknown key: {key}[/red]")
                config.restore(snapshot)
                return 1
            try:
                config.set(key, _coerce_setting_value(current, raw_val.strip()))
            except ValueError as exc:
                console.print(f"[red]Invalid value for {key}: {exc}[/red]")
                config.restore(snapshot)
                return 1
        errs = config.validate()
        if errs:
            for e in errs:
                console.print(f"[red]{e}[/red]")
            config.restore(snapshot)
            return 1
        config.save()
        console.print("[green]Saved.[/green]")

    if args.get:
        val = config.get(args.get)
        if val is None:
            console.print(f"[red]Unknown key: {args.get}[/red]")
            return 1
        console.print(json.dumps(val) if isinstance(val, (list, dict)) else str(val))
        return 0

    if args.validate:
        errs = config.validate()
        if errs:
            for e in errs:
                console.print(f"[red]{e}[/red]")
            return 1
        console.print("[green]Configuration valid.[/green]")
        return 0

    if args.show or not args.set:
        table = Table("key", "value", title="Current settings", show_header=True)
        for key in SETTINGS_KEYS:
            table.add_row(key, str(config.get(key)))
        console.print(table)
    return 0


def cli(argv: list[str]) -> int:
    """Non-interactive entry point. Returns -1 to fall through to the menu."""
    startup_probe()
    if not argv:
        return -1
    ap = build_parser()
    args = ap.parse_args(argv)

    if getattr(args, "plain_ui", False):
        menu.set_plain_ui(True)

    if args.subcommand == "list":
        src = args.list_file or args.file or "targets.txt"
        return _cmd_list(src)
    if args.subcommand == "scan":
        return _cmd_scan(args)
    if args.subcommand == "report":
        return _cmd_report(args)
    if args.subcommand == "config":
        return _cmd_config(args)

    # Top-level legacy flag compatibility
    if getattr(args, "list", None):
        return _cmd_list(args.list)
    if (
        getattr(args, "dry_run", None)
        or getattr(args, "batch", None)
        or getattr(args, "resume", "")
        or getattr(args, "source_dir", "")
    ):
        return _cmd_scan(args)
    return -1


# ------------------------------------------------------------------- main
def main() -> int:
    startup_probe()
    if sys.argv[1:]:
        rc = cli(sys.argv[1:])
        if rc >= 0:
            return rc
    bootstrap()
    menu.banner()
    while True:
        try:
            choice = menu.main_menu()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[grey62]Bye.[/grey62]")
            return 0
        if choice == "16":
            console.print("[grey62]Bye.[/grey62]")
            return 0
        handler = HANDLERS.get(choice)
        if not handler:
            continue
        try:
            handler()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            if RUNTIME["active_scan"]:
                RUNTIME["stop"].set()
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]{type(exc).__name__}: {exc}[/red]")
        menu.pause()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        sys.exit(main())
    finally:
        if RUNTIME["db"]:
            RUNTIME["db"].close()
