#!/usr/bin/env python3
"""TSMSS entry point."""
from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from collections import Counter
from pathlib import Path

from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

import config as cfgmod
from config import SEVERITY_ORDER
from core import termux_api as tap
from core.database import Database
from core.engine import TargetEngine, TargetScanResult, score
from core.evidence import EvidenceStore
from core.http_client import HttpClient
from core.logger import setup as setup_logging
from core.rate_limiter import RateLimiter
from core.report_manager import ReportManager
from core.scheduler import Scheduler
from core.scope import ScopeGuard
from core.validator import load_targets, validate
from ui import dashboard, menu
from ui.menu import console

RUNTIME = {"config": None, "db": None, "reports": None, "scope": None,
           "stop": None, "active_scan": None}


# ---------------------------------------------------------------- bootstrap
def bootstrap() -> None:
    RUNTIME["config"] = cfgmod.load()
    setup_logging(BASE / "logs", RUNTIME["config"].get("logging.level", "INFO"))
    RUNTIME["db"] = Database(BASE / "database" / "scans.db")
    RUNTIME["reports"] = ReportManager(BASE / "reports", BASE / "templates" / "report.html")
    RUNTIME["stop"] = asyncio.Event()


def build_scope(config) -> ScopeGuard:
    return ScopeGuard(
        allowed_domains=config.get("scope.allowed_domains", []),
        allow_subdomains=config.get("scope.allow_subdomains", True),
        allow_private=config.get("scope.allow_private_targets", False),
        allow_out_of_scope_redirects=config.get("scope.allow_out_of_scope_redirects", False))


def make_http_factory(config, scope, limiter):
    def factory(stop_event, counter):
        return HttpClient(config, scope, limiter, stop_event, counter)
    return factory


# ------------------------------------------------------------------- scan
async def run_scan(urls: list[str], note: str = "", auto_reports: bool = False) -> None:
    config = RUNTIME["config"]
    db: Database = RUNTIME["db"]

    if not urls:
        console.print("[yellow]No valid targets.[/yellow]")
        return
    limit = int(config.get("scope.max_targets", 500))
    if len(urls) > limit:
        console.print(f"[yellow]Trimming {len(urls)} targets to {limit}.[/yellow]")
        urls = urls[:limit]

    scope = build_scope(config)
    for u in urls:
        scope.register(u)
    RUNTIME["scope"] = scope

    # scope admission check
    admitted: list[str] = []
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
        return

    scan_id = db.create_scan(config.data, len(admitted), note)
    db.add_targets(scan_id, admitted)
    db.audit(scan_id, "scan_start", f"{len(admitted)} targets")
    RUNTIME["active_scan"] = scan_id

    await tap.wake_lock(True)
    stop_event: asyncio.Event = RUNTIME["stop"]
    stop_event.clear()

    limiter = RateLimiter(config.get("scan.max_requests_per_second", 4.0),
                          config.get("scan.per_host_requests_per_second", 1.5))
    reports_base = RUNTIME["reports"].base if RUNTIME.get("reports") is not None else (BASE / "reports")
    evidence = EvidenceStore(reports_base / scan_id / "evidence",
                             int(config.get("reporting.evidence_max_bytes", 8192)))
    engine = TargetEngine(config, cfgmod.load_rules(), scope,
                          make_http_factory(config, scope, limiter), evidence)
    counters: Counter = Counter()
    meta = {"id": scan_id, "note": note, "started": True}

    async def worker(url: str) -> TargetScanResult:
        db.set_target_status(scan_id, url, "running")
        result = await engine.scan(url, stop_event)
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
            scan_id, url, status,
            error=None if result.ok else (result.error or "scan failed"),
            score=result.score, requests=result.requests,
        )
        db.save_checkpoint(scan_id, {"last_url": url, "completed": True})
        db.audit(scan_id, "target_done", f"{url} status={status} score={result.score}")

    scheduler = Scheduler(config, stop_event, on_done)

    with Live(dashboard.render(scheduler.state, counters, scan_id),
              console=console, refresh_per_second=3, transient=False) as live:
        task = asyncio.create_task(scheduler.run(admitted, worker))
        while not task.done():
            await asyncio.sleep(0.4)
            live.update(dashboard.render(scheduler.state, counters, scan_id))
        try:
            await task
        except asyncio.CancelledError:
            pass
        live.update(dashboard.render(scheduler.state, counters, scan_id))

    if scheduler.state.completed == 0 and scheduler.state.failed > 0:
        console.print("[yellow]every target failed - check network and scope[/yellow]")

    status = "interrupted" if stop_event.is_set() else "complete"
    db.finish_scan(scan_id, status)
    db.audit(scan_id, "scan_end", status)
    await tap.wake_lock(False)

    rows = [dict(r) for r in db.findings(scan_id)]
    targets = [dict(t) for t in db.targets(scan_id)]
    from core.finding import Finding
    findings_objs = []
    for r in rows:
        data = {k: v for k, v in r.items() if k in Finding.__dataclass_fields__}
        data["target"] = r["target_url"]
        findings_objs.append(Finding(**data))
    overall, grade = score(findings_objs)

    console.print(Panel(
        f"Scan [bold]{scan_id}[/bold] {status}\n"
        f"Completed {scheduler.state.completed}  Failed {scheduler.state.failed}  "
        f"Skipped {scheduler.state.skipped}\n"
        f"Findings: {menu.severity_bar(dict(counters))}\n"
        f"Score {overall}/100 (grade {grade})  Duration {scheduler.state.elapsed}s",
        border_style="green" if status == "complete" else "yellow"))
    if auto_reports:
        for fmt, path in generate_reports(scan_id).items():
            console.print(f"[green]{fmt.upper()} report:[/green] {path}")
    else:
        console.print(f"[grey62]Reports: {reports_base}[/grey62]")

    if config.get("safety.notify_on_complete", True):
        await tap.notify("TSMSS scan finished",
                         f"{status}: {scheduler.state.completed} done, {len(rows)} findings")
    await tap.vibrate()
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
    asyncio.run(run_scan([res.normalized], "single"))


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
        asyncio.run(run_scan(urls, "multi"))


def handle_file() -> None:
    path = menu.ask("TXT file path", "targets.txt")
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
    if not menu.confirm_authorization():
        return
    asyncio.run(run_scan(urls, f"file:{path}"))


SETTINGS_KEYS: tuple[str, ...] = (
    "scan.concurrency_targets", "scan.max_requests_per_second",
    "scan.per_host_requests_per_second", "scan.request_timeout",
    "scan.batch_size", "scan.delay_between_requests",
    "scope.allow_private_targets", "scope.allow_subdomains",
    "scope.max_targets", "safety.max_total_requests_per_target",
    "active.xss", "active.sqli", "active.ssti", "active.xxe",
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
    rows = RUNTIME["db"].recent_scans(20)
    if not rows:
        console.print("[grey62]No scans yet.[/grey62]")
        return
    table = Table("id", "started", "status", "targets", "note")
    for r in rows:
        table.add_row(r["id"], r["started_at"], r["status"], str(r["total_targets"]),
                      (r["note"] or "")[:30])
    console.print(table)


def handle_findings() -> None:
    scan_id = menu.ask("Scan ID")
    rows = RUNTIME["db"].findings(scan_id)
    if not rows:
        console.print("[grey62]No findings.[/grey62]")
        return
    for r in rows:
        colour = {"CRITICAL": "bright_red", "HIGH": "dark_orange", "MEDIUM": "yellow",
                  "LOW": "cyan", "INFO": "grey62"}.get(r["severity"], "white")
        console.print(Panel(
            f"[{colour} bold]{r['severity']}[/{colour} bold] [grey50]{r['finding_id']}[/grey50]\n"
            f"[bold]{r['title']}[/bold]\n"
            f"[grey62]{r['target_url']}[/grey62]\n"
            f"confidence={r['confidence']} status={r['verification_status']}\n\n"
            f"{r['description']}\n\n"
            f"[grey50]evidence:[/grey50] {(r['evidence'] or '')[:400]}\n"
            f"[cyan]fix:[/cyan] {r['remediation']}",
            border_style=colour))


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
    reports = RUNTIME["reports"]
    return {
        "html": str(reports.html_report(meta, targets, by_target)),
        "json": str(reports.json_report(meta, targets, by_target)),
        "txt": str(reports.txt_report(meta, targets, by_target)),
        "csv": str(reports.csv_report(all_rows)),
    }


def handle_report(fmt: str) -> None:
    scan_id = menu.ask("Scan ID")
    meta, targets, by_target = _load_scan_rows(scan_id)
    if meta is None:
        return
    all_rows = [f for v in by_target.values() for f in v]
    if fmt == "json":
        path = RUNTIME["reports"].json_report(meta, targets, by_target)
    elif fmt == "txt":
        path = RUNTIME["reports"].txt_report(meta, targets, by_target)
    elif fmt == "csv":
        path = RUNTIME["reports"].csv_report(all_rows)
    else:
        path = RUNTIME["reports"].html_report(meta, targets, by_target)
    console.print(f"[green]Written:[/green] {path}")
    if asyncio.run(tap.clipboard(str(path))):
        console.print("[grey62]Path copied to clipboard.[/grey62]")


def handle_tools() -> None:
    env = tap.environment_report()
    table = Table("tool", "status")
    for tool, present in env.items():
        table.add_row(tool, "[green]yes[/green]" if present else "[grey50]no[/grey50]")
    console.print(table)
    console.print("[grey62]Missing Go tools fall back to native Python checks.[/grey62]")


def handle_env() -> None:
    env = tap.environment_report()
    console.print(Panel(json.dumps(env, indent=2), title="Termux environment",
                        border_style="cyan"))
    free = asyncio.run(tap.storage_free_mb())
    if free is not None:
        colour = "red" if free < 200 else "yellow" if free < 500 else "green"
        console.print(f"Free storage: [{colour}]{free} MB[/{colour}]")
    pct = asyncio.run(tap.battery_percent())
    if pct is not None:
        console.print(f"Battery: {pct}%")


def handle_resume() -> None:
    rows = RUNTIME["db"].resumable_scans()
    if not rows:
        console.print("[grey62]Nothing to resume.[/grey62]")
        return
    for r in rows:
        counts = RUNTIME["db"].counts(r["id"])
        console.print(f"{r['id']}  {r['started_at']}  {r['status']}  counts={counts}")
    scan_id = menu.ask("Scan ID to resume")
    targets = RUNTIME["db"].targets(scan_id)
    if not targets:
        console.print("[red]Unknown scan.[/red]")
        return
    pending = [t["url"] for t in targets if t["status"] in ("pending", "running")]
    console.print(f"[yellow]{len(pending)} target(s) outstanding.[/yellow]")
    if pending and menu.confirm_authorization():
        asyncio.run(run_scan(pending, f"resume:{scan_id}"))


def handle_stop() -> None:
    if RUNTIME["active_scan"]:
        RUNTIME["stop"].set()
        console.print("[yellow]Stop signalled; finishing in-flight requests.[/yellow]")
    else:
        console.print("[grey62]No active scan.[/grey62]")


HANDLERS = {
    "1": handle_single, "2": handle_multi, "3": handle_file, "4": handle_settings,
    "5": handle_previous, "6": handle_findings,
    "7": lambda: handle_report("html"), "8": lambda: handle_report("json"),
    "9": lambda: handle_report("txt"), "10": lambda: handle_report("csv"),
    "11": handle_tools, "12": handle_env, "13": handle_resume, "14": handle_stop,
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


def cli(argv: list[str]) -> int:
    """Non-interactive entry point. Returns -1 to fall through to the menu."""
    ap = argparse.ArgumentParser(
        prog="main.py", description="TSMSS - authorized, non-destructive web security auditing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with no arguments for the interactive menu.")
    ap.add_argument("-b", "--batch", metavar="FILE", help="scan every URL in FILE, then exit")
    ap.add_argument("-l", "--list", metavar="FILE", help="validate and print FILE, then exit")
    ap.add_argument("-d", "--dry-run", metavar="FILE", help="validate FILE without scanning")
    ap.add_argument("-y", "--yes", action="store_true", help="skip the authorization prompt")
    ap.add_argument("--no-reports", action="store_true", help="skip report generation")
    ap.add_argument("--min-confidence", default="",
                    choices=["", "CONFIRMED", "HIGH CONFIDENCE", "MEDIUM CONFIDENCE",
                             "LOW CONFIDENCE"],
                    help="drop findings below this confidence")
    ap.add_argument("--fail-on", default="", choices=["", "CRITICAL", "HIGH", "MEDIUM"],
                    help="exit 2 when a finding at or above this severity exists")
    args = ap.parse_args(argv)

    source = args.list or args.dry_run or args.batch
    if not source:
        return -1

    bootstrap()
    try:
        urls, rejected = load_targets(source)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1

    _print_rejections(rejected)
    if not urls:
        console.print("[red]No valid targets.[/red]")
        return 1

    if args.list:
        for i, u in enumerate(urls, 1):
            console.print(f"{i:>3}. {u}")
        console.print(f"[grey62]{len(urls)} valid, {len(rejected)} rejected[/grey62]")
        return 0

    if args.dry_run:
        console.print(f"[green]{len(urls)} valid[/green], [yellow]{len(rejected)} rejected[/yellow]")
        return 0

    console.print(f"[bold]{len(urls)}[/bold] target(s) from [cyan]{source}[/cyan]")
    if not args.yes and not menu.confirm_authorization():
        console.print("[yellow]Authorization not confirmed.[/yellow]")
        return 1

    RUNTIME["config"].set("scan.min_confidence", args.min_confidence)
    asyncio.run(run_scan(urls, f"batch:{source}", auto_reports=not args.no_reports))
    if args.fail_on:
        from config import SEVERITY_ORDER
        limit = SEVERITY_ORDER.index(args.fail_on)
        hits = [f for s in db_scans() for f in s if SEVERITY_ORDER.index(f) <= limit]
        if hits:
            console.print(f"[red]fail-on {args.fail_on}: {len(hits)} finding(s)[/red]")
            return 2
    return 0


# ------------------------------------------------------------------- main
def main() -> int:
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
        if choice == "15":
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