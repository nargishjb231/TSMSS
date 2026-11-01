"""Live Rich dashboard."""
from __future__ import annotations

from collections import Counter

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import SEVERITY_ORDER

COLOUR = {"CRITICAL": "bright_red", "HIGH": "dark_orange", "MEDIUM": "yellow",
          "LOW": "cyan", "INFO": "grey62"}


def render(state, severity_counter: Counter, scan_id: str) -> Panel:
    done = state.done
    pct = (done / state.total * 100) if state.total else 0.0
    width = 34
    filled = int(width * pct / 100)
    bar = Text("█" * filled, style="green") + Text("░" * (width - filled), style="grey30")

    head = Table.grid(expand=True)
    head.add_column(justify="left")
    head.add_column(justify="right")
    head.add_row(Text(f"Scan {scan_id}", style="bold cyan"),
                 Text(f"{state.elapsed}s elapsed", style="grey62"))

    kpis = Table.grid(expand=True)
    for _ in range(6):
        kpis.add_column(justify="center")
    kpis.add_row(*[
        _kpi("Targets", str(state.total), "white"),
        _kpi("Done", str(state.completed), "green"),
        _kpi("Failed", str(state.failed), "red"),
        _kpi("Pending", str(state.pending), "yellow"),
        _kpi("Requests", str(state.requests), "cyan"),
        _kpi("Progress", f"{pct:.0f}%", "magenta"),
    ])

    sev = Table.grid(expand=True)
    for _ in range(5):
        sev.add_column(justify="center")
    sev.add_row(*[Text(f"{s}\n{severity_counter.get(s, 0)}",
                       style=COLOUR[s], justify="center") for s in SEVERITY_ORDER])

    current = state.current[-3:] if state.current else ["(idle)"]
    cur = Text("\n".join(f"  > {u}" for u in current), style="grey78")

    return Panel(
        Group(head, Text(""), bar, Text(f"{done}/{state.total} targets", style="grey62"),
              Text(""), kpis, Text(""), sev, Text(""), Text("Active targets:", style="bold"),
              cur),
        title="[bold]TSMSS batch scan[/bold]", border_style="cyan",
        subtitle="[grey50]Ctrl-C = graceful stop[/grey50]")


def _kpi(label: str, value: str, colour: str) -> Text:
    return Text.assemble((value + "\n", f"bold {colour}"), (label, "grey50"))