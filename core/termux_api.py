"""Optional Termux:API bridge. Every call degrades silently."""
from __future__ import annotations

import asyncio
import json
import shutil


def available(cmd: str) -> bool:
    return shutil.which(cmd) is not None


async def _run(cmd: list[str], timeout: float = 10) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode("utf-8", "replace").strip()
    except (asyncio.TimeoutError, OSError):
        return ""


async def battery() -> dict:
    if not available("termux-battery-status"):
        return {}
    try:
        return json.loads(await _run(["termux-battery-status"]))
    except (json.JSONDecodeError, ValueError):
        return {}


async def battery_percent() -> int | None:
    data = await battery()
    pct = data.get("percentage")
    return int(pct) if isinstance(pct, (int, float)) else None


async def device_info() -> dict:
    if not available("termux-device-info"):
        return {}
    try:
        return json.loads(await _run(["termux-device-info"]))
    except (json.JSONDecodeError, ValueError):
        return {}


async def storage_free_mb() -> int | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "df", "-Pk", ".", stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        parts = out.decode().splitlines()
        return int(parts[1].split()[3]) // 1024 if len(parts) > 1 else None
    except (asyncio.TimeoutError, OSError, ValueError, IndexError):
        return None


async def notify(title: str, body: str) -> bool:
    if not available("termux-notification"):
        return False
    await _run(["termux-notification", "--title", title, "--content", body], timeout=8)
    return True


async def wake_lock(on: bool = True) -> None:
    cmd = "termux-wake-lock" if on else "termux-wake-unlock"
    if available(cmd):
        await _run([cmd])


async def vibrate() -> None:
    if available("termux-vibrate"):
        await _run(["termux-vibrate", "-d", "180"], timeout=4)


async def clipboard(text: str) -> bool:
    if not available("termux-clipboard-set"):
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "termux-clipboard-set", stdin=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.communicate(text.encode()), timeout=8)
        return True
    except (asyncio.TimeoutError, OSError):
        return False


def environment_report() -> dict:
    return {
        "termux": True,
        "termux_api": available("termux-battery-status"),
        "notifications": available("termux-notification"),
        "wake_lock": available("termux-wake-lock"),
        "nmap": available("nmap"),
        "whois": available("whois"),
        "dig": available("dig"),
        "openssl": available("openssl"),
        "git": available("git"),
        "nuclei": available("nuclei"),
        "subfinder": available("subfinder"),
        "httpx_go": available("httpx"),
        "katana": available("katana"),
    }