"""Cloudflare CIDR matching, DNS topology classification, and split-origin detection (Work Item L)."""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Any

from core.finding import CONFIRMED, INFO, LOW, MEDIUM, Finding

CF_IPV4_CIDRS: tuple[str, ...] = (
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "131.0.72.0/22",
)

CF_IPV6_CIDRS: tuple[str, ...] = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

CF_NETWORKS = tuple(ipaddress.ip_network(c) for c in (CF_IPV4_CIDRS + CF_IPV6_CIDRS))

CF_PROXIED = "CF_PROXIED"
CF_DNS_ONLY = "CF_DNS_ONLY"
DIRECT = "DIRECT"


def is_cloudflare_ip(ip_str: str) -> bool:
    """Return True if *ip_str* belongs to a published Cloudflare IPv4/IPv6 CIDR (L1)."""
    try:
        addr = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False
    return any(addr in net for net in CF_NETWORKS)


def is_cloudflare_ns(ns_records: list[str]) -> bool:
    """Return True if any NS record ends with `.ns.cloudflare.com`."""
    for ns in ns_records or []:
        clean = str(ns).strip().lower().rstrip(".")
        if clean.endswith(".ns.cloudflare.com") or clean == "ns.cloudflare.com":
            return True
    return False


def _ipv4_slash16(ip_str: str) -> str | None:
    try:
        addr = ipaddress.ip_address(str(ip_str).strip())
        if isinstance(addr, ipaddress.IPv4Address):
            parts = str(addr).split(".")
            return f"{parts[0]}.{parts[1]}.0.0/16"
    except ValueError:
        pass
    return None


@dataclass
class TopologyResult:
    classification: str = DIRECT
    origin_hidden: bool = False
    scan_target: str = ""
    origin_ips: list[str] = field(default_factory=list)
    cf_ips: list[str] = field(default_factory=list)
    distinct_slash16s: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def analyze_topology(
    ns_records: list[str],
    a_records: list[str],
    aaaa_records: list[str] | None = None,
    *,
    target_url: str = "https://example.com/",
    host: str = "example.com",
) -> TopologyResult:
    """Classify target DNS topology (`CF_PROXIED | CF_DNS_ONLY | DIRECT`) and emit L3/L4/L5 findings."""
    all_ips = [str(ip).strip() for ip in (list(a_records or []) + list(aaaa_records or [])) if str(ip).strip()]
    cf_ns = is_cloudflare_ns(ns_records)
    cf_ips = [ip for ip in all_ips if is_cloudflare_ip(ip)]
    non_cf_ips = [ip for ip in all_ips if not is_cloudflare_ip(ip)]

    res = TopologyResult(cf_ips=cf_ips, origin_ips=non_cf_ips)

    if cf_ns and all_ips and not non_cf_ips:
        res.classification = CF_PROXIED
        res.origin_hidden = True
        res.scan_target = host
    elif cf_ns and non_cf_ips:
        res.classification = CF_DNS_ONLY
        res.origin_hidden = False
        res.scan_target = non_cf_ips[0]
        res.findings.append(
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="Origin IP exposed behind Cloudflare (proxy bypassed)",
                severity=MEDIUM,
                cwe="CWE-200",
                confidence=CONFIRMED,
                description=(
                    "Authoritative nameservers belong to Cloudflare (*.ns.cloudflare.com), "
                    "but the A/AAAA record resolves directly to a non-Cloudflare origin IP "
                    "(grey-clouded DNS-only mode), bypassing Cloudflare WAF and DDoS protection."
                ),
                evidence=f"NS: {', '.join(ns_records)}\nExposed Origin IP(s): {', '.join(non_cf_ips)}\nscan_target={res.scan_target}",
                detection_method="Cloudflare NS + CIDR topology check",
                remediation="Enable Cloudflare proxy (orange cloud) on the DNS record and restrict origin firewall to Cloudflare IP ranges.",
                tags=["dns", "topology", "origin-exposed"],
            )
        )
        res.findings.append(
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="Cloudflare DNS only - no WAF in path",
                severity=INFO,
                cwe="CWE-693",
                confidence=CONFIRMED,
                description="Traffic routes directly to the origin IP without traversing Cloudflare's reverse-proxy WAF.",
                evidence=f"Topology: CF_DNS_ONLY | Origin IP: {res.scan_target}",
                detection_method="Cloudflare NS + CIDR topology check",
                remediation="Route HTTP/HTTPS traffic through Cloudflare proxy or deploy an origin WAF.",
                tags=["dns", "topology", "no-waf"],
            )
        )
    else:
        res.classification = DIRECT
        res.origin_hidden = False
        res.scan_target = non_cf_ips[0] if non_cf_ips else host

    # L5: >=2 A records in different /16s (and not both inside Cloudflare anycast)
    v4_records = [str(ip).strip() for ip in (a_records or []) if str(ip).strip()]
    if len(v4_records) >= 2:
        non_cf_v4 = [ip for ip in v4_records if not is_cloudflare_ip(ip)]
        # If not all A records are inside CF anycast, check distinct /16 networks across all A records
        if non_cf_v4:
            slash16s = []
            for ip in v4_records:
                s16 = _ipv4_slash16(ip)
                if s16 and s16 not in slash16s:
                    slash16s.append(s16)
            res.distinct_slash16s = slash16s
            if len(slash16s) >= 2:
                res.findings.append(
                    Finding(
                        target=target_url,
                        url=target_url,
                        category="DNS Security",
                        module="dns_security",
                        title="Multiple A records in distinct networks, possible split origin or dangling record",
                        severity=LOW,
                        cwe="CWE-200",
                        confidence=CONFIRMED,
                        description=(
                            f"The hostname resolves to {len(v4_records)} IPv4 addresses across "
                            f"{len(slash16s)} distinct /16 networks ({', '.join(slash16s)}), "
                            "which may indicate a split origin or a stale/dangling A record."
                        ),
                        evidence=f"A records: {', '.join(v4_records)}\nNetworks (/16): {', '.join(slash16s)}",
                        detection_method="IPv4 /16 prefix comparison",
                        remediation="Verify all A records belong to active, identically hardened origin servers and remove stale IP addresses.",
                        tags=["dns", "topology", "split-origin"],
                    )
                )

    return res
