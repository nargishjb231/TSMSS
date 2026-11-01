"""Mobile-first terminal menus, prompts, and plain-text fallback."""
from __future__ import annotations

import os
import sys

from config import SEVERITY_ORDER
from core.diagnostics import memory_info_mb, storage_info_mb

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.theme import Theme

    NAVY_THEME = Theme({
        "navy.border": "bold bright_cyan",
        "navy.title": "bold bright_cyan on #0a192f",
        "navy.sub": "cyan",
        "navy.key": "bold bright_cyan",
        "navy.dim": "grey66",
    })
    console = Console(theme=NAVY_THEME)
    RICH_AVAILABLE = True
except Exception:
    console = None  # type: ignore[assignment]
    RICH_AVAILABLE = False

PLAIN_UI = os.environ.get("TSMSS_PLAIN_UI", "").strip() in ("1", "true", "yes")

BANNER = r"""
  ______  ___  __  __  ___  ___ 
 |_   _| / __||  \/  |/ __|/ __|
   | |   \__ \| |\/| |\__ \\__ \
   |_|   |___/|_|  |_||___/|___/  v2.0
"""

MENU = [
    ("1", "Single Website Audit"),
    ("2", "Batch Website Audit"),
    ("3", "Passive Reconnaissance"),
    ("4", "HTTP Security"),
    ("5", "SSL/TLS Security"),
    ("6", "DNS Security"),
    ("7", "API Security"),
    ("8", "Source Code Analysis"),
    ("9", "Dependency Audit"),
    ("10", "Findings Dashboard"),
    ("11", "AI Report Generator"),
    ("12", "Scan History"),
    ("13", "Tool Manager"),
    ("14", "Device Diagnostics"),
    ("15", "Settings"),
    ("16", "Exit"),
]


def set_plain_ui(enabled: bool) -> None:
    global PLAIN_UI
    PLAIN_UI = bool(enabled)


def _telemetry_line() -> str:
    mem = memory_info_mb()
    disk = storage_info_mb(".")
    ram_part = (
        f"RAM: {mem['available_mb']}MB free/{mem['total_mb']}MB"
        if mem.get("available_mb") is not None and mem.get("total_mb") is not None
        else "RAM: n/a"
    )
    disk_part = f"Storage: {disk['free_mb']}MB free" if disk.get("free_mb") is not None else "Storage: n/a"
    return f"{ram_part}  |  {disk_part}"


def banner(subtitle: str = "") -> None:
    telem = _telemetry_line()
    if PLAIN_UI or not RICH_AVAILABLE or console is None:
        print(BANNER)
        print("TSMSS 2.0 Ultimate Edition — Non-Root Android/Termux Security Platform")
        print(telem)
        if subtitle:
            print(f"[{subtitle}]")
        return
    try:
        console.print(Panel.fit(
            f"[bold bright_cyan]{BANNER}[/bold bright_cyan]"
            f"[bold white]TSMSS 2.0 Ultimate Edition[/bold white]\n"
            f"[cyan]Authorized Non-Root Mobile Security & Bug Bounty Platform[/cyan]\n"
            f"[grey66]{telem}[/grey66]"
            + (f"\n[bold yellow]{subtitle}[/bold yellow]" if subtitle else ""),
            border_style="bright_cyan",
            style="on #071120",
        ))
    except Exception:
        print("TSMSS 2.0 Ultimate Edition")
        if subtitle:
            print(subtitle)


def main_menu() -> str:
    choices = [k for k, _ in MENU]
    if PLAIN_UI or not RICH_AVAILABLE or console is None:
        print("\n=== TSMSS 2.0 MAIN MENU ===")
        for key, label in MENU:
            print(f"  {key:>2}. {label}")
        raw = input("Select [1-16] (default 1): ").strip() or "1"
        return raw if raw in choices else "1"

    table = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
    table.add_column(style="bold bright_cyan", justify="right", width=3)
    table.add_column(style="white", overflow="fold")
    for key, label in MENU:
        table.add_row(f"{key}.", label)
    width = min(getattr(console.size, "width", 68) or 68, 68)
    console.print(Panel(
        table,
        title="[bold bright_cyan]TSMSS 2.0 Mobile Menu[/bold bright_cyan]",
        subtitle=f"[grey62]{_telemetry_line()}[/grey62]",
        border_style="cyan",
        style="on #071120",
        width=width,
    ))
    return Prompt.ask("[bold cyan]Select[/bold cyan]", choices=choices, default="1")


def severity_bar(counts: dict) -> str:
    parts = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if n:
            parts.append(f"[bold]{sev}[/bold]={n}")
    return "  ".join(parts) if parts else "no findings"


def confirm_authorization() -> bool:
    if PLAIN_UI or not RICH_AVAILABLE or console is None:
        ans = input("Confirm you are authorized to assess the target(s)? [y/N]: ").strip().lower()
        return ans in ("y", "yes")
    console.print(Panel(
        "[bold bright_cyan]Authorization & Safe Scope Confirmation[/bold bright_cyan]\n\n"
        "TSMSS 2.0 performs authorized, non-destructive security assessments:\n"
        "passive reconnaissance, configuration & header analysis, TLS/DNS inspection,\n"
        "and safe indicator checks. Never run against unauthorized targets.\n\n"
        "[yellow]Confirm you are explicitly authorized to assess the target(s).[/yellow]",
        border_style="yellow",
        style="on #071120",
    ))
    return Confirm.ask("Authorized?", default=False)


def ask(text: str, default: str = "") -> str:
    if PLAIN_UI or not RICH_AVAILABLE or console is None:
        raw = input(f"{text} [{default}]: ").strip()
        return raw if raw else default
    return Prompt.ask(text, default=default)


def pause() -> None:
    if PLAIN_UI or not RICH_AVAILABLE or console is None:
        input("\nPress Enter to continue...")
        return
    Prompt.ask("\n[grey50]Enter to continue[/grey50]", default="", show_default=False)
