"""Per-target execution context."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core.scope import ScopeGuard


@dataclass
class Target:
    url: str

    @property
    def parts(self):
        return urlsplit(self.url)

    @property
    def host(self) -> str:
        return (self.parts.hostname or "").lower()

    @property
    def port(self) -> int:
        return self.parts.port or (443 if self.parts.scheme == "https" else 80)

    @property
    def scheme(self) -> str:
        return self.parts.scheme

    @property
    def root(self) -> str:
        """Origin URL as a string, always ending in a single '/'.

        Callers do str(target.root) and concatenate paths, so this must never
        return a SplitResult (whose str() is a repr).
        """
        return self.parts._replace(path="/", query="", fragment="").geturl()

    @property
    def https_url(self) -> str:
        p = self.parts
        return p._replace(scheme="https", netloc=p.netloc.replace(f":{p.port}", "") if p.port == 80 else p.netloc).geturl()

    @property
    def plain_url(self) -> str:
        p = self.parts
        return p._replace(scheme="http").geturl()

    @property
    def registrable(self) -> str:
        host = self.host
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host


@dataclass
class ScanContext:
    target: Target
    config: object
    scope: ScopeGuard
    http: object
    stop_event: asyncio.Event
    counter: dict
    homepage: object = None
    dns_records: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    tls_protocols: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    frameworks: list = field(default_factory=list)
    cdn: str = ""
    cors: dict = field(default_factory=dict)
    api_doc_url: str = ""
    login_url: str = ""
    login_fields: list = field(default_factory=list)
    csrf_token_present: bool | None = None
    evidence: object = None
    soft404: object = None
    soft404_calibration: str = "stable"
    seen_paths: set = field(default_factory=set)
    edge_challenged: bool = False
    edge_banner: str = ""
    topology: str = ""
    scan_target: str = ""
    origin_hidden: bool = False
    resolved_ips: list = field(default_factory=list)
    wildcard_dns: bool = False
    brute_force_enabled: bool = True
    checks_account: dict = field(default_factory=lambda: {"ran": 0, "skipped": 0, "failed": 0})