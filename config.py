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
        "authorized": False,
        "allow_private_targets": False,
        "allow_subdomains": True,
        "allow_out_of_scope_redirects": False,
        "allowed_domains": [],
        "max_targets": 500,
    },
    "active": {
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
    "logging": {"level": "INFO", "audit_log": True},
}

SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


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

    def save(self) -> None:
        with _LOCK:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            tmp = SETTINGS_FILE.with_suffix(".tmp")
            tmp.write_text(yaml.safe_dump(self.data, sort_keys=False), encoding="utf-8")
            tmp.replace(SETTINGS_FILE)

    def validate(self) -> list[str]:
        errs: list[str] = []
        c = self.get("scan.concurrency_targets", 3)
        if not isinstance(c, int) or not 1 <= c <= 20:
            errs.append("scan.concurrency_targets must be 1..20")
        rps = self.get("scan.max_requests_per_second", 4.0)
        if not isinstance(rps, (int, float)) or rps <= 0:
            errs.append("scan.max_requests_per_second must be > 0")
        if self.get("scan.max_retries", 3) > 10:
            errs.append("scan.max_retries should be <= 10")
        if self.get("scan.request_timeout", 20) < 3:
            errs.append("scan.request_timeout should be >= 3s")
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