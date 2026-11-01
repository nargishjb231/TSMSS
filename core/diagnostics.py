"""Local Android 16+ / Termux device diagnostics.

Strictly isolated from website vulnerability scanning so local host properties
are never confused with target website findings.
"""
from __future__ import annotations

import ctypes
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any


def _run_cmd(args: list[str], timeout: float = 3.0) -> str:
    try:
        res = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return (res.stdout or "").strip()
    except Exception:
        return ""


def memory_info_mb() -> dict[str, int | None]:
    """Read available and total RAM in MB without requiring root or psutil."""
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        try:
            vals: dict[str, int] = {}
            for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" not in line:
                    continue
                k, rest = line.split(":", 1)
                parts = rest.strip().split()
                if parts and parts[0].isdigit():
                    vals[k.strip()] = int(parts[0]) // 1024
            total = vals.get("MemTotal")
            avail = vals.get("MemAvailable", vals.get("MemFree"))
            used = (total - avail) if (total is not None and avail is not None) else None
            return {"total_mb": total, "available_mb": avail, "used_mb": used}
        except Exception:
            pass

    if sys.platform == "win32":
        try:
            class _MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = _MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                total = int(stat.ullTotalPhys // (1024 * 1024))
                avail = int(stat.ullAvailPhys // (1024 * 1024))
                return {"total_mb": total, "available_mb": avail, "used_mb": total - avail}
        except Exception:
            pass

    return {"total_mb": None, "available_mb": None, "used_mb": None}


def storage_info_mb(path: Path | str = ".") -> dict[str, int | None]:
    try:
        usage = shutil.disk_usage(path)
        return {
            "total_mb": int(usage.total // (1024 * 1024)),
            "free_mb": int(usage.free // (1024 * 1024)),
            "used_mb": int(usage.used // (1024 * 1024)),
        }
    except Exception:
        return {"total_mb": None, "free_mb": None, "used_mb": None}


def detect_android_env() -> dict[str, Any]:
    prefix = os.environ.get("PREFIX", "")
    is_termux = bool(
        os.environ.get("TERMUX_VERSION")
        or prefix.startswith("/data/data/com.termux")
        or Path("/data/data/com.termux/files/usr").exists()
    )
    android_rel = _run_cmd(["getprop", "ro.build.version.release"]) if is_termux else ""
    android_sdk = _run_cmd(["getprop", "ro.build.version.sdk"]) if is_termux else ""
    device_model = _run_cmd(["getprop", "ro.product.model"]) if is_termux else ""
    is_root = False
    if hasattr(os, "geteuid"):
        try:
            is_root = os.geteuid() == 0
        except Exception:
            is_root = False
    return {
        "is_termux": is_termux,
        "termux_version": os.environ.get("TERMUX_VERSION") or ("detected" if is_termux else "not-termux"),
        "android_release": android_rel or ("Android (unknown release)" if is_termux else platform.system()),
        "android_sdk": int(android_sdk) if android_sdk.isdigit() else None,
        "device_model": device_model or platform.node() or "generic",
        "cpu_arch": platform.machine() or "unknown",
        "cpu_cores": os.cpu_count() or 1,
        "python_version": platform.python_version(),
        "is_root": is_root,
    }


def detect_installed_tools() -> dict[str, bool]:
    binaries = (
        "python", "bash", "git", "curl", "wget", "openssl", "dig", "whois",
        "jq", "sqlite3", "nmap", "subfinder", "dnsx", "httpx", "katana",
        "nuclei", "gitleaks", "osv-scanner", "pip-audit", "trivy", "semgrep",
        "termux-battery-status", "termux-notification", "termux-wake-lock",
    )
    return {b: shutil.which(b) is not None for b in binaries}


def check_network_dns() -> dict[str, Any]:
    resolv_paths = [
        Path("/data/data/com.termux/files/usr/etc/resolv.conf"),
        Path("/etc/resolv.conf"),
    ]
    has_resolv_conf = any(p.exists() for p in resolv_paths)
    can_resolve = False
    try:
        socket.getaddrinfo("localhost", 80)
        can_resolve = True
    except OSError:
        can_resolve = False
    return {
        "resolv_conf_present": has_resolv_conf,
        "local_resolver_ok": can_resolve,
        "fallback_resolvers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    }


def capability_matrix(env: dict[str, Any], tools: dict[str, bool]) -> list[dict[str, str]]:
    is_root = bool(env.get("is_root"))
    has_tapi = bool(tools.get("termux-battery-status"))
    return [
        {
            "feature": "Passive HTTP/TLS/DNS Security Auditing",
            "status": "SUPPORTED",
            "note": "Runs in user-space via Python httpx, ssl, and dnspython without root.",
        },
        {
            "feature": "Local Source Code SAST & Lockfile Auditing",
            "status": "SUPPORTED",
            "note": "Built-in Python AST + manifest analyzer works 100% offline.",
        },
        {
            "feature": "SQLite Persistence, History & Interrupted Scan Recovery",
            "status": "SUPPORTED",
            "note": "Automatic WAL/DELETE fallback for shared FUSE storage.",
        },
        {
            "feature": "TCP Service Discovery (Connect Scan)",
            "status": "PARTIALLY SUPPORTED",
            "note": "Uses non-root TCP connect() probes; SYN stealth scan (-sS) requires root.",
        },
        {
            "feature": "Android Background Execution (Phantom Process Killer)",
            "status": "PARTIALLY SUPPORTED",
            "note": "Android 12-16+ caps background phantom processes (32); acquire wake-lock and use bounded concurrency.",
        },
        {
            "feature": "PCAPdroid / mitmproxy Traffic Integration",
            "status": "PARTIALLY SUPPORTED",
            "note": "PCAPdroid works via non-root VpnService export; mitmproxy requires lab user-CA configuration.",
        },
        {
            "feature": "Termux:API Hardware Telemetry (Battery/Wake-Lock/Notifications)",
            "status": "SUPPORTED" if has_tapi else "REQUIRES TESTING",
            "note": "Termux:API detected." if has_tapi else "Optional Termux:API companion app not detected; scanner runs normally without it.",
        },
        {
            "feature": "Raw Socket / ICMP / SYN Stealth / Packet Capture (tcpdump)",
            "status": "SUPPORTED" if is_root else "UNSUPPORTED",
            "note": "Root detected." if is_root else "Blocked by Android SELinux (no CAP_NET_RAW on non-root devices).",
        },
        {
            "feature": "Desktop JVM / OCaml Scanners (OWASP ZAP, native Semgrep)",
            "status": "UNSUPPORTED",
            "note": "Unsupported on stock non-root Termux Bionic libc; replaced by native TSMSS modules.",
        },
    ]


def collect_device_diagnostics(workspace: Path | str = ".") -> dict[str, Any]:
    """Return a structured local device diagnostic report (never mixed with target findings)."""
    env = detect_android_env()
    mem = memory_info_mb()
    disk = storage_info_mb(workspace)
    tools = detect_installed_tools()
    net = check_network_dns()
    matrix = capability_matrix(env, tools)

    warnings: list[str] = []
    if not env["is_root"]:
        warnings.append("Non-root mode active: raw sockets/SYN scans disabled; using safe user-space TCP/HTTP connect probes.")
    if env["is_termux"] and not net["resolv_conf_present"]:
        warnings.append("No /etc/resolv.conf found (normal on Android); dnspython is configured with explicit DNS resolvers.")
    if not tools.get("termux-battery-status"):
        warnings.append("Termux:API is not installed (optional); battery/notification hooks are safely bypassed.")
    if mem["available_mb"] is not None and mem["available_mb"] < 384:
        warnings.append(f"Low available RAM ({mem['available_mb']} MB); use '--profile quick' or '--profile passive' with concurrency <= 2.")
    if disk["free_mb"] is not None and disk["free_mb"] < 256:
        warnings.append(f"Low free storage ({disk['free_mb']} MB); prune old reports or evidence files.")
    if env.get("android_sdk") and env["android_sdk"] >= 31:
        warnings.append(
            f"Android SDK {env['android_sdk']} enforces Phantom Process Killer & Doze limits; keep Termux in foreground or enable termux-wake-lock."
        )

    return {
        "scope_notice": "LOCAL_DEVICE_DIAGNOSTICS_ONLY (not a website vulnerability scan)",
        "environment": env,
        "memory": mem,
        "storage": disk,
        "network": net,
        "tools": tools,
        "compatibility_matrix": matrix,
        "warnings": warnings,
    }
