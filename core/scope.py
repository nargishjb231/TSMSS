"""Scope enforcement: allowlist, inclusion/exclusion patterns, private-IP guard, redirect validation."""
from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class ScopeError(Exception):
    pass


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str


@dataclass
class ScopeProfile:
    name: str = "default"
    allowed_domains: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    allow_subdomains: bool = False
    allow_private: bool = False
    allow_out_of_scope_redirects: bool = False
    max_requests_per_target: int = 900
    rate_limit_rps: float = 4.0


def is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip == ipaddress.ip_address("100.64.0.0"))


def _norm_host(host: str) -> str:
    return (host or "").strip().rstrip(".").lower()


def _pattern_matches(url: str, host: str, path: str, pattern: str) -> bool:
    pat = (pattern or "").strip().lower()
    if not pat:
        return False
    if "://" in pat:
        if fnmatch.fnmatch(url.lower(), pat):
            return True
    elif "/" in pat:
        target_hp = f"{host}{path or '/'}".lower()
        p_norm = (path or "/").lower()
        if fnmatch.fnmatch(target_hp, pat) or fnmatch.fnmatch(p_norm, pat):
            return True
        if p_norm.startswith(pat.rstrip("*")):
            return True
    else:
        if fnmatch.fnmatch(host, pat) or (pat.startswith("*.") and host == pat[2:]):
            return True
    return False


class ScopeGuard:
    def __init__(self, allowed_domains=None, allow_subdomains=True,
                 allow_private=False, allow_out_of_scope_redirects=False,
                 include_patterns=None, exclude_patterns=None,
                 program_name: str = "default"):
        self.program_name = program_name
        self.allowed = {_norm_host(d) for d in (allowed_domains or []) if d}
        self.allow_subdomains = allow_subdomains
        self.allow_private = allow_private
        self.allow_out_of_scope_redirects = allow_out_of_scope_redirects
        self.include_patterns = [str(p).strip() for p in (include_patterns or []) if str(p).strip()]
        self.exclude_patterns = [str(p).strip() for p in (exclude_patterns or []) if str(p).strip()]
        self._resolved: dict[str, list[str]] = {}

    @classmethod
    def from_config(cls, config) -> "ScopeGuard":
        return cls(
            allowed_domains=config.get("scope.allowed_domains", []),
            allow_subdomains=bool(config.get("scope.allow_subdomains", True)),
            allow_private=bool(config.get("scope.allow_private_targets", False)),
            allow_out_of_scope_redirects=bool(config.get("scope.allow_out_of_scope_redirects", False)),
            include_patterns=config.get("scope.include_patterns", []),
            exclude_patterns=config.get("scope.exclude_patterns", []),
            program_name=str(config.get("scope.program_name", "default")),
        )

    # ---- target admission -------------------------------------------------
    def register(self, url: str) -> None:
        host = _norm_host(urlsplit(url).hostname or "")
        if host:
            self.allowed.add(host)

    def _is_excluded(self, url: str, host: str, path: str) -> str | None:
        for pat in self.exclude_patterns:
            if _pattern_matches(url, host, path, pat):
                return pat
        return None

    def _is_explicitly_included(self, url: str, host: str, path: str) -> bool:
        for pat in self.include_patterns:
            if _pattern_matches(url, host, path, pat):
                return True
        return False

    def _matches(self, host: str, url: str = "", path: str = "/") -> bool:
        if self.include_patterns and not self._is_explicitly_included(url or f"https://{host}{path}", host, path):
            return False
        if not self.allowed:
            return True
        if host in self.allowed:
            return True
        if self.allow_subdomains:
            return any(host.endswith("." + a) for a in self.allowed)
        return False

    def check_discovered_subdomain(self, subdomain: str, parent_domain: str = "") -> ScopeDecision:
        """Discovered subdomains are never automatically in scope unless explicitly permitted."""
        sub = _norm_host(subdomain)
        if not sub:
            return ScopeDecision(False, "empty subdomain")
        excl = self._is_excluded(f"https://{sub}/", sub, "/")
        if excl:
            return ScopeDecision(False, f"excluded by scope pattern '{excl}'")
        if not self.allow_subdomains:
            if sub in self.allowed or self._is_explicitly_included(f"https://{sub}/", sub, "/"):
                return ScopeDecision(True, "explicitly in allowlist")
            return ScopeDecision(False, "discovered subdomains require scope.allow_subdomains=true")
        if self.allowed and not any(sub == a or sub.endswith("." + a) for a in self.allowed):
            return ScopeDecision(False, f"'{sub}' outside authorized domain allowlist")
        return ScopeDecision(True, "in scope (authorized subdomain)")

    def resolve(self, host: str) -> list[str]:
        if host in self._resolved:
            return self._resolved[host]
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            ips = sorted({i[4][0] for i in infos})
        except OSError:
            ips = []
        self._resolved[host] = ips
        return ips

    def check_target(self, url: str) -> ScopeDecision:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return ScopeDecision(False, f"unsupported scheme '{parts.scheme}'")
        host = _norm_host(parts.hostname or "")
        if not host:
            return ScopeDecision(False, "no hostname")
        path = parts.path or "/"
        excl = self._is_excluded(url, host, path)
        if excl:
            return ScopeDecision(False, f"'{url}' excluded by scope pattern '{excl}'")
        if not self._matches(host, url, path):
            return ScopeDecision(False, f"'{host}' not in authorized allowlist")
        if not self.allow_private:
            ips = self.resolve(host)
            if ips and all(is_private_ip(i) for i in ips):
                return ScopeDecision(False, f"private/internal address {ips[0]} (enable scope.allow_private_targets)")
        return ScopeDecision(True, "in scope")

    def check_redirect(self, origin: str, destination: str) -> ScopeDecision:
        dest_parts = urlsplit(destination)
        dest_host = _norm_host(dest_parts.hostname or "")
        dest_path = dest_parts.path or "/"
        origin_host = _norm_host(urlsplit(origin).hostname or "")
        excl = self._is_excluded(destination, dest_host, dest_path)
        if excl:
            return ScopeDecision(False, f"redirect target excluded by scope pattern '{excl}'")
        if dest_host == origin_host:
            return ScopeDecision(True, "same host")
        if self.allow_out_of_scope_redirects:
            return ScopeDecision(True, "out-of-scope redirects permitted")
        if self._matches(dest_host, destination, dest_path):
            return ScopeDecision(True, "redirect inside allowlist")
        return ScopeDecision(False, f"redirect escapes scope to '{dest_host}'")

    def snapshot(self) -> dict:
        return {
            "program_name": self.program_name,
            "allowed_domains": sorted(self.allowed),
            "include_patterns": list(self.include_patterns),
            "exclude_patterns": list(self.exclude_patterns),
            "allow_subdomains": self.allow_subdomains,
            "allow_private": self.allow_private,
            "allow_out_of_scope_redirects": self.allow_out_of_scope_redirects,
        }