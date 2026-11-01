"""TSMSS configuration: defaults, YAML overlay, validation, persistence."""
from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
SETTINGS_FILE = CONFIG_DIR / "settings.yaml"
RULES_FILE = CONFIG_DIR / "rules.yaml"

_LOCK = threading.RLock()

DEFAULTS: dict[str, Any] = {
    "scan": {
        "concurrency_targets": 3,
        "max_requests_per_second": 4.0,
        "per_host_requests_per_second": 1.5,
        "request_timeout": 20,
        "max_retries": 3,
        "retry_backoff": 1.6,
        "max_redirects": 5,
        "target_timeout": 900,
        "module_timeout": 120,
        "batch_size": 5,
        "delay_between_requests": 0.12,
        "max_response_bytes": 1_048_576,
        "user_agent": "TSMSS/1.0 (+authorized-security-audit; Termux)",
    },
    "scope": {
        "program_name": "default",
        "authorized": False,
        "allow_private_targets": False,
        "allow_subdomains": True,
        "allow_out_of_scope_redirects": False,
        "allowed_domains": [],
        "include_patterns": [],
        "exclude_patterns": [],
        "max_targets": 500,
    },
    "active": {
        "safe_mode": False,
        "xss": True,
        "sqli": True,
        "ssti": True,
        "open_redirect": True,
        "path_traversal": True,
        "command_injection": True,
        "crlf": True,
        "xxe": True,
        "ldap": True,
        "subdomain_takeover": True,
        "smuggling": True,
        "cache_poisoning": True,
        "param_discovery": True,
        "max_params_per_target": 25,
        "max_payloads_per_param": 4,
    },
    "dns": {
        "resolvers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "dkim_selectors": ["default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail", "dkim"],
        "timeout": 6,
        "lifetime": 12,
        "subdomain_wordlist": [
            "www", "mail", "api", "dev", "staging", "test", "admin", "portal",
            "vpn", "cdn", "static", "assets", "blog", "shop", "app", "m",
            "beta", "demo", "git", "ci", "status", "docs", "support", "ftp",
            "smtp", "webmail", "remote", "gateway", "auth", "sso", "db",
        ],
    },
    "infra": {
        "enable_nmap": True,
        "nmap_ports": "80,443,8080,8443,8000,3000,5000",
        "nmap_host_timeout": "90s",
        "enable_whois": True,
        "enable_go_tools": True,
    },
    "safety": {
        "require_authorization": True,
        "max_total_requests_per_target": 900,
        "pause_on_battery_below": 10,
        "check_battery": True,
        "notify_on_complete": True,
        "stop_on_data_saver": False,
    },
    "reporting": {
        "open_html_on_finish": False,
        "include_response_bodies": True,
        "evidence_max_bytes": 8192,
        "redact_patterns": [],
    },
    "modules": {"disabled": []},
    "tools": {
        "mode": "auto",
        "max_runtime": 180,
        "rate_limit": 5,
        "allow_root_tools": False,
        "enabled": [],
        "disabled": [],
    },
    "logging": {"level": "INFO", "audit_log": True},
}

SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

KNOWN_MODULES: tuple[str, ...] = (
    "reconnaissance", "dns_security", "ssl_tls", "http_security", "cookies", "cors",
    "information_disclosure", "framework_audit", "api_security",
    "authentication", "authorization", "dependency_audit",
    "vulnerability_indicators", "source_code", "infrastructure", "external_tools",
)
VALID_TOOL_MODES: tuple[str, ...] = ("auto", "on", "off")

PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "scan": {
            "concurrency_targets": 5,
            "max_requests_per_second": 8.0,
            "per_host_requests_per_second": 3.0,
            "delay_between_requests": 0.05,
            "request_timeout": 10,
            "module_timeout": 45,
        },
        "active": {"max_params_per_target": 8},
        "modules": {"disabled": ["infrastructure", "external_tools", "dns_security"]},
    },
    "standard": {
        "scan": {
            "concurrency_targets": 3,
            "max_requests_per_second": 4.0,
            "per_host_requests_per_second": 1.5,
            "delay_between_requests": 0.12,
            "request_timeout": 20,
            "module_timeout": 120,
        },
        "active": {"safe_mode": False, "max_params_per_target": 25},
        "modules": {"disabled": []},
    },
    "passive": {
        "scan": {
            "concurrency_targets": 2,
            "max_requests_per_second": 1.5,
            "per_host_requests_per_second": 0.8,
            "delay_between_requests": 0.4,
            "request_timeout": 20,
            "module_timeout": 120,
        },
        "active": {"safe_mode": True, "max_params_per_target": 15},
        "infra": {"enable_nmap": False},
        "modules": {"disabled": ["external_tools"]},
    },
    "stealth": {
        "scan": {
            "concurrency_targets": 1,
            "max_requests_per_second": 0.8,
            "per_host_requests_per_second": 0.4,
            "delay_between_requests": 0.75,
            "request_timeout": 25,
            "module_timeout": 180,
        },
        "active": {"safe_mode": True, "max_params_per_target": 10},
        "infra": {"enable_nmap": False},
        "modules": {"disabled": ["external_tools"]},
    },
    "deep": {
        "scan": {
            "concurrency_targets": 3,
            "max_requests_per_second": 4.0,
            "per_host_requests_per_second": 1.5,
            "delay_between_requests": 0.10,
            "request_timeout": 25,
            "module_timeout": 180,
        },
        "active": {"max_params_per_target": 40, "max_payloads_per_param": 6},
        "modules": {"disabled": []},
    },
    "source": {
        "scan": {
            "concurrency_targets": 1,
            "max_requests_per_second": 2.0,
            "per_host_requests_per_second": 1.0,
            "request_timeout": 15,
            "module_timeout": 120,
        },
        "active": {"safe_mode": True},
        "modules": {
            "disabled": [
                "dns_security", "ssl_tls", "http_security", "cookies", "cors",
                "information_disclosure", "framework_audit", "api_security",
                "authentication", "authorization", "vulnerability_indicators",
                "infrastructure", "external_tools",
            ]
        },
    },
}
VALID_PROFILES: tuple[str, ...] = tuple(PROFILES.keys())


def _known_tool_ids() -> set[str]:
    tools_file = CONFIG_DIR / "tools.yaml"
    if not tools_file.exists():
        return set()
    try:
        raw = yaml.safe_load(tools_file.read_text(encoding="utf-8")) or []
        return {str(item["id"]) for item in raw if isinstance(item, dict) and "id" in item}
    except Exception:
        return set()


def _deep_merge(base: dict, overlay: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (overlay or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    """Dotted-path config accessor with atomic save."""

    def __init__(self, data: dict[str, Any] | None = None):
        self.data = _deep_merge(DEFAULTS, data or {})

    def get(self, path: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set(self, path: str, value: Any) -> None:
        parts = path.split(".")
        cur = self.data
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value

    def update(self, mapping: dict[str, Any]) -> None:
        self.data = _deep_merge(self.data, mapping)

    def apply_profile(self, name: str) -> None:
        key = (name or "").strip().lower()
        if key not in PROFILES:
            raise ValueError(f"Unknown profile '{name}'. Choose from: {', '.join(VALID_PROFILES)}")
        self.update(PROFILES[key])

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self.data)

    def restore(self, snap: dict[str, Any]) -> None:
        self.data = copy.deepcopy(snap)

    def save(self) -> None:
        with _LOCK:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            tmp = SETTINGS_FILE.with_suffix(".tmp")
            tmp.write_text(yaml.safe_dump(self.data, sort_keys=False), encoding="utf-8")
            tmp.replace(SETTINGS_FILE)

    def validate(self) -> list[str]:
        errs: list[str] = []
        c = self.get("scan.concurrency_targets", 3)
        if isinstance(c, bool) or not isinstance(c, int) or not 1 <= c <= 20:
            errs.append("scan.concurrency_targets must be 1..20")
        rps = self.get("scan.max_requests_per_second", 4.0)
        if isinstance(rps, bool) or not isinstance(rps, (int, float)) or rps <= 0:
            errs.append("scan.max_requests_per_second must be > 0")
        retries = self.get("scan.max_retries", 3)
        if isinstance(retries, bool) or not isinstance(retries, int) or not 0 <= retries <= 10:
            errs.append("scan.max_retries should be 0..10")
        timeout = self.get("scan.request_timeout", 20)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 3:
            errs.append("scan.request_timeout should be >= 3s")

        disabled_mods = self.get("modules.disabled", [])
        if not isinstance(disabled_mods, list) or any(not isinstance(m, str) for m in disabled_mods):
            errs.append("modules.disabled must be a list of module names")
        else:
            unknown_mods = [m for m in disabled_mods if m not in KNOWN_MODULES]
            if unknown_mods:
                errs.append(f"modules.disabled contains unknown module(s): {', '.join(unknown_mods)}")

        t_mode = self.get("tools.mode", "auto")
        if not isinstance(t_mode, str) or t_mode not in VALID_TOOL_MODES:
            errs.append(f"tools.mode must be one of: {', '.join(VALID_TOOL_MODES)}")
        t_runtime = self.get("tools.max_runtime", 180)
        if isinstance(t_runtime, bool) or not isinstance(t_runtime, int) or not 5 <= t_runtime <= 3600:
            errs.append("tools.max_runtime must be 5..3600")
        t_rate = self.get("tools.rate_limit", 5)
        if isinstance(t_rate, bool) or not isinstance(t_rate, int) or not 1 <= t_rate <= 1000:
            errs.append("tools.rate_limit must be 1..1000")
        t_root = self.get("tools.allow_root_tools", False)
        if not isinstance(t_root, bool):
            errs.append("tools.allow_root_tools must be a boolean")

        known_tools = _known_tool_ids()
        for list_key in ("tools.enabled", "tools.disabled"):
            val = self.get(list_key, [])
            if not isinstance(val, list) or any(not isinstance(x, str) for x in val):
                errs.append(f"{list_key} must be a list of tool IDs")
            elif known_tools:
                unknown = [x for x in val if x not in known_tools]
                if unknown:
                    errs.append(f"{list_key} contains unknown tool(s): {', '.join(unknown)}")
        return errs


def load(path: Path | None = None) -> Config:
    p = path or SETTINGS_FILE
    if p.exists():
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                raise ValueError("settings root must be a mapping")
            return Config(data)
        except Exception:
            return Config()
    return Config()


def load_rules() -> dict[str, Any]:
    if not RULES_FILE.exists():
        return {}
    try:
        return yaml.safe_load(RULES_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}