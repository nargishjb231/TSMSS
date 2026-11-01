"""Compact dark-navy/cyan mobile live Rich dashboard."""
from __future__ import annotations

from collections import Counter

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import SEVERITY_ORDER
from core.diagnostics import memory_info_mb, storage_info_mb

COLOUR = {
    "CRITICAL": "bright_red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "bright_cyan",
    "INFO": "grey70",
}


def render(state, severity_counter: Counter, scan_id: str, status_label: str = "RUNNING") -> Panel:
    done = state.done
    pct = (done / state.total * 100) if state.total else 0.0
    width = 28
    filled = int(width * pct / 100)
    bar = Text("█" * filled, style="bright_cyan") + Text("░" * (width - filled), style="grey27")

    total_findings = sum(severity_counter.values())
    mem = memory_info_mb()
    disk = storage_info_mb(".")
    ram_str = f"{mem['available_mb']}MB free" if mem.get("available_mb") is not None else "n/a"
    disk_str = f"{disk['free_mb']}MB free" if disk.get("free_mb") is not None else "n/a"

    head = Table.grid(expand=True)
    head.add_column(justify="left")
    head.add_column(justify="right")
    head.add_row(
        Text(f"Scan {scan_id} [{status_label}]", style="bold bright_cyan"),
        Text(f"{state.elapsed}s", style="cyan"),
    )

    kpis_row1 = Table.grid(expand=True)
    for _ in range(4):
        kpis_row1.add_column(justify="center")
    kpis_row1.add_row(
        _kpi("Total", str(state.total), "white"),
        _kpi("Completed", str(state.completed), "bright_green"),
        _kpi("Pending", str(state.pending), "yellow"),
        _kpi("Failed", str(state.failed), "bright_red"),
    )

    kpis_row2 = Table.grid(expand=True)
    for _ in range(4):
        kpis_row2.add_column(justify="center")
    kpis_row2.add_row(
        _kpi("Findings", str(total_findings), "bright_cyan"),
        _kpi("Requests", str(state.requests), "cyan"),
        _kpi("RAM", ram_str, "white"),
        _kpi("Storage", disk_str, "white"),
    )

    sev = Table.grid(expand=True)
    for _ in range(5):
        sev.add_column(justify="center")
    sev.add_row(*[
        Text(f"{s}\n{severity_counter.get(s, 0)}", style=COLOUR[s], justify="center")
        for s in SEVERITY_ORDER
    ])

    current = state.current[-2:] if state.current else ["(idle)"]
    cur = Text("\n".join(f"  > {u}" for u in current), style="cyan")

    return Panel(
        Group(
            head,
            Text(""),
            bar,
            Text(f"Progress: {done}/{state.total} targets ({pct:.0f}%)", style="grey70"),
            Text(""),
            kpis_row1,
            Text(""),
            kpis_row2,
            Text(""),
            sev,
            Text(""),
            Text("Current Target(s):", style="bold bright_cyan"),
            cur,
        ),
        title="[bold bright_cyan]TSMSS 2.0 Live Mobile Dashboard[/bold bright_cyan]",
        border_style="bright_cyan",
        style="on #071120",
        subtitle="[grey58]Ctrl-C = safe checkpoint & stop[/grey58]",
    )


def _kpi(label: str, value: str, colour: str) -> Text:
    return Text.assemble((value + "\n", f"bold {colour}"), (label, "grey62"))
