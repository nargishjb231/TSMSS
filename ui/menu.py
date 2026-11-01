"""Terminal menus and prompts."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from config import SEVERITY_ORDER

console = Console()

BANNER = r"""
 ______  ___  __  __  ___  ___
|_   _| / __||  \/  |/ __|/ __|
  | |   \__ \| |\/| |\__ \\__ \
  |_|   |___/|_|  |_||___/|___/
"""

MENU = [
    ("1", "Single Website Audit"),
    ("2", "Multiple Website Audit (paste URLs)"),
    ("3", "Load Targets From TXT"),
    ("4", "Configure Scan Settings"),
    ("5", "View Previous Scans"),
    ("6", "View Vulnerability Findings"),
    ("7", "Generate HTML Report"),
    ("8", "Generate JSON Report"),
    ("9", "Generate TXT Report"),
    ("10", "Generate CSV Report"),
    ("11", "Check Installed Tools"),
    ("12", "Check Termux Environment"),
    ("13", "Resume Interrupted Scan"),
    ("14", "Stop Current Scan"),
    ("15", "Exit"),
]


def banner(subtitle: str = "") -> None:
    console.print(Panel.fit(
        f"[bold cyan]{BANNER}[/bold cyan]"
        f"[bold]Termux Super Master Security Scanner[/bold]\n"
        f"[grey62]authorized, non-destructive web assessment[/grey62]"
        + (f"\n[yellow]{subtitle}[/yellow]" if subtitle else ""),
        border_style="cyan"))


def main_menu() -> str:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", justify="right", width=4)
    table.add_column()
    for key, label in MENU:
        table.add_row(key, label)
    console.print(Panel(table, title="Menu", border_style="grey35"))
    return Prompt.ask("Select", choices=[k for k, _ in MENU], default="1")


def severity_bar(counts: dict) -> str:
    parts = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if n:
            parts.append(f"[bold]{sev}[/bold]={n}")
    return "  ".join(parts) if parts else "no findings"


def confirm_authorization() -> bool:
    console.print(Panel(
        "[bold]Authorization confirmation[/bold]\n\n"
        "TSMSS only performs non-destructive checks: GET/HEAD/OPTIONS requests, DNS lookups,\n"
        "TLS handshakes and a small number of payload probes. No writes, no accounts,\n"
        "no exploitation, no load testing.\n\n"
        "[yellow]Confirm you are authorized to assess the target(s).[/yellow]",
        border_style="yellow"))
    return Confirm.ask("Authorized?", default=False)


def ask(text: str, default: str = "") -> str:
    return Prompt.ask(text, default=default)


def pause() -> None:
    Prompt.ask("\n[grey50]Enter to continue[/grey50]", default="", show_default=False)