"""dnspython wrapper with Android-safe resolver bootstrap."""
from __future__ import annotations

import asyncio
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver

_CACHE: dict[str, list[str]] = {}


def _nameservers(configured: list[str]) -> list[str]:
    servers: list[str] = []
    rc = Path("/etc/resolv.conf")
    if rc.exists():
        try:
            for line in rc.read_text(errors="replace").splitlines():
                if line.strip().startswith("nameserver"):
                    servers.append(line.split()[1])
        except OSError:
            pass
    servers += configured or []
    return servers or ["1.1.1.1", "8.8.8.8"]


def make_resolver(config) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = _nameservers(config.get("dns.resolvers", []))
    r.timeout = float(config.get("dns.timeout", 6))
    r.lifetime = float(config.get("dns.lifetime", 12))
    return r


async def query(resolver, name: str, rtype: str, want_dnssec: bool = False) -> list[str]:
    key = f"{name}|{rtype}"
    if key in _CACHE:
        return _CACHE[key]
    try:
        answer = await resolver.resolve(name, rtype, raise_on_no_answer=False, search=False)
        values = [r.to_text().strip('"') for r in (answer.rrset or [])]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        values = []
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException, OSError):
        values = []
    _CACHE[key] = values
    return values


async def resolve_chain(resolver, name: str) -> list[str]:
    """Follow CNAMEs up to 8 hops, return the final target list."""
    seen, current = [], name
    for _ in range(8):
        cnames = await query(resolver, current, "CNAME")
        if not cnames:
            break
        current = cnames[0].rstrip(".")
        if current in seen:
            break
        seen.append(current)
    return seen


def clear_cache() -> None:
    _CACHE.clear()