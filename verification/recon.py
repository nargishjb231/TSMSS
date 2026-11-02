"""Phase 1: Proof-Oriented Reconnaissance Pipeline.

1.1 Topology first: A/AAAA, NS, CNAME, MX, TXT. Classify CF_PROXIED, CF_DNS_ONLY, DIRECT.
    CF_DNS_ONLY -> MEDIUM origin exposed, set scan_target = origin IP.
    CF_PROXIED -> scan the edge, 8080/8443 INFO, origin findings unavailable.
1.2 Wildcard DNS: 2 random labels per apex. Both resolve -> wildcard=true, brute force off, INFO "wildcard DNS".
1.3 Passive: subfinder, gau, waybackurls, alterx. Canonicalize and dedupe by resolved A-set.
1.4 Live: httpx probing.
1.5 Crawl: katana extraction.
1.6 Params: arjun + gau/wayback parameters.
1.7 Ports: nmap -Pn -sT (connect-scan only, no raw sockets, unprivileged Termux).
1.8 Edge detection: challenge markers, edge=true, banner "EDGE-CHALLENGE (app not observed)",
    extract meta-CSP as csp_source=meta (never app header).
"""
from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from core.finding import CONFIRMED, HIGH, INFO, LOW, MEDIUM, Finding
from dns.topology import CF_DNS_ONLY, CF_PROXIED, DIRECT, TopologyResult, analyze_topology
from modules.dns_security import canonicalize_subdomain, dedupe_subdomains, evaluate_wildcard_dns
from probe.challenge import EDGE_BANNER, detect_challenge, extract_meta_csp

logger = logging.getLogger("tsmss.verification.recon")

# Standard nmap connect-scan port list for unprivileged Termux
CONNECT_SCAN_PORTS = [21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]


@dataclass
class ReconProfile:
    target_url: str
    host: str
    apex: str
    topology: str = DIRECT
    scan_target: str = ""
    origin_ip: str | None = None
    is_wildcard: bool = False
    brute_force_enabled: bool = True
    edge_challenge: bool = False
    edge_banner: str = ""
    csp_meta: str = ""
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    subdomains: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def extract_apex(host: str) -> str:
    """Extract apex domain (e.g. 'sub.example.com' -> 'example.com')."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # Common 2-part ccTLDs
    cctlds = {"co.uk", "com.bd", "org.bd", "edu.bd", "gov.bd", "com.au", "co.jp"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in cctlds:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def process_dns_recon(
    target_url: str,
    host: str,
    ns_records: list[str],
    a_records: list[str],
    aaaa_records: list[str] | None = None,
    wildcard_probe1: list[str] | None = None,
    wildcard_probe2: list[str] | None = None,
) -> tuple[TopologyResult, bool, bool, list[Finding]]:
    """Process DNS topology (1.1) and Wildcard DNS check (1.2)."""
    apex = extract_apex(host)
    topo = analyze_topology(
        ns_records=ns_records,
        a_records=a_records,
        aaaa_records=aaaa_records,
        target_url=target_url,
        host=host,
    )

    wc_detected = False
    brute_enabled = True
    wc_findings: list[Finding] = []

    if wildcard_probe1 is not None and wildcard_probe2 is not None:
        wc_detected, brute_enabled, _, wc_findings = evaluate_wildcard_dns(
            probe1_ips=wildcard_probe1,
            probe2_ips=wildcard_probe2,
            target_url=target_url,
            apex=apex,
        )

    all_findings = list(topo.findings) + list(wc_findings)
    return topo, wc_detected, brute_enabled, all_findings


def evaluate_edge_challenge(
    status: int,
    headers: dict[str, str] | None,
    body: str,
) -> tuple[bool, str, str]:
    """1.8 Edge detection: detect challenge, extract meta-CSP, and set banner."""
    is_chal, provider = detect_challenge(status=status, headers=headers, body=body)
    meta_csp = extract_meta_csp(body)
    banner = EDGE_BANNER if is_chal else ""
    return is_chal, banner, meta_csp


def evaluate_port_severity(port: int, topology: str) -> str:
    """8080/8443 on CF_PROXIED -> INFO; on DIRECT -> normal (LOW or MEDIUM depending on banner)."""
    if port in (8080, 8443) and topology == CF_PROXIED:
        return INFO
    return LOW
