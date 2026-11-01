"""Scope enforcement: allowlist, domain matching, private-IP guard, redirect validation."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


class ScopeError(Exception):
    pass


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str


def is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip == ipaddress.ip_address("100.64.0.0"))


def _norm_host(host: str) -> str:
    return (host or "").strip().rstrip(".").lower()


class ScopeGuard:
    def __init__(self, allowed_domains=None, allow_subdomains=True,
                 allow_private=False, allow_out_of_scope_redirects=False):
        self.allowed = {_norm_host(d) for d in (allowed_domains or []) if d}
        self.allow_subdomains = allow_subdomains
        self.allow_private = allow_private
        self.allow_out_of_scope_redirects = allow_out_of_scope_redirects
        self._resolved: dict[str, list[str]] = {}

    # ---- target admission -------------------------------------------------
    def register(self, url: str) -> None:
        host = _norm_host(urlsplit(url).hostname or "")
        if host:
            self.allowed.add(host)

    def _matches(self, host: str) -> bool:
        if not self.allowed:
            return True
        if host in self.allowed:
            return True
        if self.allow_subdomains:
            return any(host.endswith("." + a) for a in self.allowed)
        return False

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
        if not self._matches(host):
            return ScopeDecision(False, f"'{host}' not in authorized allowlist")
        if not self.allow_private:
            ips = self.resolve(host)
            if ips and all(is_private_ip(i) for i in ips):
                return ScopeDecision(False, f"private/internal address {ips[0]} (enable scope.allow_private_targets)")
        return ScopeDecision(True, "in scope")

    def check_redirect(self, origin: str, destination: str) -> ScopeDecision:
        dest_host = _norm_host(urlsplit(destination).hostname or "")
        origin_host = _norm_host(urlsplit(origin).hostname or "")
        if dest_host == origin_host:
            return ScopeDecision(True, "same host")
        if self.allow_out_of_scope_redirects:
            return ScopeDecision(True, "out-of-scope redirects permitted")
        if self._matches(dest_host):
            return ScopeDecision(True, "redirect inside allowlist")
        return ScopeDecision(False, f"redirect escapes scope to '{dest_host}'")

    def snapshot(self) -> dict:
        return {"allowed_domains": sorted(self.allowed),
                "allow_subdomains": self.allow_subdomains,
                "allow_private": self.allow_private}