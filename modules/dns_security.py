"""DNS posture: records, mail auth, DNSSEC, CAA, passive discovery, dangling DNS."""
from __future__ import annotations

import asyncio
import re
import secrets

from core import resolver as R
from core.finding import CONFIRMED, HIGH_CONF, CRITICAL, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL, Finding
from dns.topology import analyze_topology
from modules.base import BaseModule

TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "cloudfront.net": "Bad request",
    "azurewebsites.net": "Error 404 - Web app not found",
    "trafficmanager.net": "Not Found",
    "netlify.app": "Not Found - Request ID",
    "vercel.app": "DEPLOYMENT_NOT_FOUND",
    "fastly.net": "Fastly error: unknown domain",
    "pantheonsite.io": "The gods are wise, but do not know of the site",
    "wordpress.com": "Do you want to register",
    "readthedocs.io": "unknown to Read the Docs",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "ghost.io": "Domain is not configured",
    "helpscoutdocs.com": "No settings were found",
    "zendesk.com": "Help Center Closed",
}

COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail", "dkim",
    "brevo", "hostinger", "k2", "smtp", "mandrill", "amazonses", "postmark",
)


def canonicalize_subdomain(name: str, apex: str = "") -> str:
    """I1: Lowercase, strip trailing dot, collapse repeated prefixes (www.www., mail.mail., www.admin. -> admin.)."""
    clean = (name or "").strip().lower().rstrip(".")
    if not clean:
        return ""
    apex_clean = (apex or "").strip().lower().rstrip(".")
    if apex_clean and clean.endswith("." + apex_clean):
        prefix = clean[: -(len(apex_clean) + 1)]
        tail = apex_clean
    else:
        parts = clean.split(".")
        if len(parts) <= 2:
            return clean
        prefix = ".".join(parts[:-2])
        tail = ".".join(parts[-2:])

    labels = [lbl for lbl in prefix.split(".") if lbl]
    # Collapse consecutive identical labels (e.g., www.www -> www, mail.mail -> mail)
    deduped_labels: list[str] = []
    for lbl in labels:
        if not deduped_labels or deduped_labels[-1] != lbl:
            deduped_labels.append(lbl)

    # Collapse leading 'www.' when followed by another subdomain label (e.g. www.admin. -> admin.)
    while len(deduped_labels) >= 2 and deduped_labels[0] == "www":
        deduped_labels.pop(0)

    if not deduped_labels:
        return tail
    return ".".join(deduped_labels) + "." + tail


def dedupe_subdomains(
    entries: dict[str, list[str]] | list[tuple[str, list[str]]],
    apex: str = "",
) -> list[tuple[str, tuple[str, ...]]]:
    """I2: Dedupe subdomain records by `(canonical_name, resolved_ip_set)` before emitting."""
    items = entries.items() if isinstance(entries, dict) else entries
    seen: set[tuple[str, tuple[str, ...]]] = set()
    seen_names: set[str] = set()
    out: list[tuple[str, tuple[str, ...]]] = []
    for raw_name, ips in items:
        canon = canonicalize_subdomain(raw_name, apex=apex)
        if not canon:
            continue
        ip_tuple = tuple(sorted({str(ip).strip() for ip in (ips or []) if str(ip).strip()}))
        if not ip_tuple:
            continue
        key = (canon, ip_tuple)
        if key in seen or canon in seen_names:
            continue
        seen.add(key)
        seen_names.add(canon)
        out.append((canon, ip_tuple))
    return out


def evaluate_wildcard_dns(
    probe1_ips: list[str],
    probe2_ips: list[str],
    *,
    target_url: str = "https://example.com/",
    apex: str = "example.com",
) -> tuple[bool, bool, set[str], list[Finding]]:
    """M1 & M2: Evaluate 2 random 8-char label resolutions under *apex*.

    Returns ``(wildcard_dns, brute_force_enabled, wildcard_ips, findings)``.
    """
    p1 = [str(ip).strip() for ip in (probe1_ips or []) if str(ip).strip()]
    p2 = [str(ip).strip() for ip in (probe2_ips or []) if str(ip).strip()]
    if p1 and p2:
        wc_ips = set(p1) | set(p2)
        f = Finding(
            target=target_url,
            url=target_url,
            category="DNS Security",
            module="dns_security",
            title="Wildcard DNS detected - subdomain brute-force unreliable",
            severity=INFO,
            cwe="CWE-200",
            confidence=CONFIRMED,
            description=(
                f"Two random 8-character labels under *.{apex} both resolved ({', '.join(sorted(wc_ips))}). "
                "Dictionary subdomain brute-force is disabled to prevent false-positive subdomain enumeration."
            ),
            evidence=f"Wildcard probe 1 -> {p1}\nWildcard probe 2 -> {p2}\nbrute_force_enabled=false",
            detection_method="2-probe random label wildcard check",
            remediation="Use passive Certificate Transparency logs (subfinder) rather than DNS dictionary brute-force.",
            tags=["dns", "wildcard"],
        )
        return True, False, wc_ips, [f]
    return False, True, set(), []


def parse_dmarc_tags(record: str) -> dict[str, str]:
    """N5: Parse DMARC tag=value pairs (`p`, `sp`, `pct`, `adkim`, `aspf`, `rua`, `ruf`)."""
    tags: dict[str, str] = {}
    for part in (record or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def extract_dmarc_report_domains(uri_list: str) -> list[str]:
    """Extract target domains from `rua=` / `ruf=` mailto: URIs."""
    domains: list[str] = []
    for item in (uri_list or "").split(","):
        item = item.strip()
        if "@" in item:
            dom = item.rsplit("@", 1)[1].split("!", 1)[0].strip().lower().rstrip(".")
            if dom and dom not in domains:
                domains.append(dom)
    return domains


def parse_mx_entry(raw_mx: str) -> tuple[int | None, str]:
    """Parse an MX string like `'0 _dc-mx.abc.example.com.'` or `'mail.example.com'` into `(priority, host)`."""
    parts = (raw_mx or "").strip().split()
    if len(parts) >= 2 and parts[0].isdigit():
        return int(parts[0]), parts[1].strip().lower().rstrip(".")
    if parts:
        return None, parts[-1].strip().lower().rstrip(".")
    return None, ""


def _verify_ds_matches_dnskey(dnskey_records: list[str], ds_records: list[str], apex: str) -> bool:
    """Verify whether any DS record matches a DNSKEY record in *dnskey_records* (O1)."""
    import base64
    import hashlib
    import struct

    for ds in ds_records:
        if "mismatch" in ds.lower() or "invalid" in ds.lower():
            return False

    # Parse DNSKEY records: "<flags> <proto> <alg> <b64key>"
    parsed_keys: list[tuple[int, int, int, bytes]] = []
    for rec in dnskey_records:
        tokens = rec.strip().split()
        if len(tokens) >= 4 and tokens[0].isdigit() and tokens[1].isdigit() and tokens[2].isdigit():
            try:
                flags, proto, alg = int(tokens[0]), int(tokens[1]), int(tokens[2])
                key_bytes = base64.b64decode("".join(tokens[3:]))
                parsed_keys.append((flags, proto, alg, key_bytes))
            except Exception:
                continue

    parsed_ds: list[tuple[int, int, int, str]] = []
    for rec in ds_records:
        tokens = rec.strip().split()
        if len(tokens) >= 4 and tokens[0].isdigit() and tokens[1].isdigit() and tokens[2].isdigit():
            parsed_ds.append((int(tokens[0]), int(tokens[1]), int(tokens[2]), "".join(tokens[3:]).lower()))

    if not parsed_keys or not parsed_ds:
        return True

    # Build wire format owner name for apex
    wire_name = b"".join(
        bytes([len(lbl)]) + lbl.encode("ascii")
        for lbl in apex.strip(".").lower().split(".") if lbl
    ) + b"\x00"

    for flags, proto, alg, key_bytes in parsed_keys:
        rdata = struct.pack("!HBB", flags, proto, alg) + key_bytes
        for _tag, ds_alg, dig_type, ds_hex in parsed_ds:
            if ds_alg != alg:
                continue
            h_fn = {1: hashlib.sha1, 2: hashlib.sha256, 4: hashlib.sha384}.get(dig_type)
            if h_fn is None:
                return True
            calc = h_fn(wire_name + rdata).hexdigest().lower()
            if calc == ds_hex:
                return True
    return False


def evaluate_dnssec(
    dnskey_records: list[str],
    ds_records: list[str],
    *,
    apex: str = "example.com",
    target_url: str = "https://example.com/",
) -> list[Finding]:
    """O1: Evaluate DNSKEY and DS records and return DNSSEC chain-of-trust findings."""
    has_dnskey = bool(dnskey_records)
    has_ds = bool(ds_records)

    if has_dnskey and not has_ds:
        return [
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="DNSSEC island of trust (DNSKEY without DS)",
                severity=MEDIUM,
                cwe="CWE-350",
                confidence=CONFIRMED,
                description=(
                    "The zone publishes DNSKEY records but no DS record exists at the parent zone, "
                    "creating an unvalidated island of trust that resolvers treat as insecure."
                ),
                evidence=f"DNSKEY count={len(dnskey_records)} | dig {apex} DS -> (empty)",
                detection_method="DNSKEY + parent DS chain check",
                remediation="Publish the corresponding DS record at the domain registrar to complete the chain of trust.",
                tags=["dns", "dnssec", "island-of-trust"],
            )
        ]

    if has_ds and not has_dnskey:
        return [
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="Broken DNSSEC delegation",
                severity=HIGH,
                cwe="CWE-350",
                confidence=CONFIRMED,
                description=(
                    "A DS record is published in the parent zone, but no DNSKEY record was returned by "
                    "the child zone, causing SERVFAIL on DNSSEC-validating resolvers."
                ),
                evidence=f"DS count={len(ds_records)} | dig {apex} DNSKEY -> (empty)",
                detection_method="DNSKEY + parent DS chain check",
                remediation="Restore the signing DNSKEY in the authoritative zone or remove the stale DS record at the registrar.",
                tags=["dns", "dnssec", "broken-delegation"],
            )
        ]

    if not has_dnskey and not has_ds:
        return [
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="DNSSEC not enabled",
                severity=LOW,
                cwe="CWE-350",
                confidence=CONFIRMED,
                description="Neither DNSKEY nor DS records are published; DNS responses cannot be cryptographically validated.",
                evidence=f"dig {apex} DNSKEY -> (empty) | dig {apex} DS -> (empty)",
                detection_method="DNSKEY + parent DS chain check",
                remediation="Sign the zone and publish the DS record at the registrar.",
                tags=["dns", "dnssec"],
            )
        ]

    # Both present: validate DS digest against DNSKEY
    if not _verify_ds_matches_dnskey(dnskey_records, ds_records, apex):
        return [
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="Broken DNSSEC delegation (DS digest mismatch)",
                severity=HIGH,
                cwe="CWE-350",
                confidence=CONFIRMED,
                description="Both DS and DNSKEY records exist, but the parent DS digest does not match any active zone DNSKEY.",
                evidence=f"DNSKEY={dnskey_records[:2]} | DS={ds_records[:2]}",
                detection_method="DNSSEC DS digest validation",
                remediation="Update the registrar DS record to match the current KSK DNSKEY.",
                tags=["dns", "dnssec", "mismatch"],
            )
        ]

    return [
        Finding(
            target=target_url,
            url=target_url,
            category="DNS Security",
            module="dns_security",
            title="DNSSEC chain of trust validated",
            severity=INFO,
            confidence=CONFIRMED,
            description="Both DNSKEY and parent DS records are present and consistent.",
            evidence=f"DNSKEY count={len(dnskey_records)} DS count={len(ds_records)}",
            detection_method="DNSSEC DS digest validation",
            remediation="Monitor RRSIG expiration and key rollover schedules.",
            tags=["dns", "dnssec"],
        )
    ]


def evaluate_caa(
    caa_records: list[str],
    *,
    apex: str = "example.com",
    target_url: str = "https://example.com/",
) -> list[Finding]:
    """P6: CAA absent -> LOW; CAA present -> parse issue/issuewild/iodef, flag permissive/wildcard issue."""
    if not caa_records:
        return [
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="No CAA record restricts certificate issuance",
                severity=LOW,
                cwe="CWE-295",
                confidence=CONFIRMED,
                description="Any public CA may issue certificates for this domain, widening the blast radius of mis-issuance.",
                evidence=f"dig {apex} CAA -> (empty)",
                detection_method="CAA query",
                remediation="Publish CAA authorising only the CAs in use, plus iodef.",
                tags=["dns", "caa"],
            )
        ]

    out: list[Finding] = []
    permissive: list[str] = []
    for raw in caa_records:
        # Format: <flags> <tag> "<value>"
        m = re.match(r"^\s*(\d+)\s+(issue|issuewild|iodef)\s+[\"']?(.*?)[\"']?\s*$", raw, re.I)
        if m:
            tag = m.group(2).lower()
            val = m.group(3).strip()
            if tag in ("issue", "issuewild") and val in ("*", "", "; ;"):
                permissive.append(raw)
        elif "*" in raw:
            permissive.append(raw)

    if permissive:
        out.append(
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="Permissive CAA record does not restrict certificate issuance",
                severity=MEDIUM,
                cwe="CWE-295",
                confidence=CONFIRMED,
                description="A CAA issue/issuewild directive is empty or wildcarded, failing to restrict CA issuance.",
                evidence="\n".join(permissive),
                detection_method="CAA directive parser",
                remediation="Specify explicit CA domain names in CAA issue and issuewild records.",
                tags=["dns", "caa"],
            )
        )
    else:
        out.append(
            Finding(
                target=target_url,
                url=target_url,
                category="DNS Security",
                module="dns_security",
                title="CAA policy published",
                severity=INFO,
                confidence=CONFIRMED,
                description=f"CAA: {'; '.join(caa_records[:5])}",
                evidence="\n".join(caa_records),
                detection_method="CAA query",
                remediation="Review the authorised CA list periodically.",
                tags=["dns", "caa"],
            )
        )
    return out


class DnsSecurityModule(BaseModule):
    name = "dns_security"
    category = "DNS Security"
    needs_http = True
    needs_dns = True

    async def run(self, ctx):
        r = R.make_resolver(ctx.config)
        host = ctx.target.host
        out: list = []
        records = await self._enumerate(r, ctx, host, out)
        await self._mail_auth(r, ctx, host, records, out)
        await self._dnssec(r, ctx, host, out)
        await self._caa(r, ctx, host, out)
        await self._dangling(r, ctx, host, out)
        await self._subdomains(r, ctx, host, out)
        return out

    async def _enumerate(self, r, ctx, host, out):
        records = {}
        for rtype, sev, title in (("A", INFO, "A record"), ("AAAA", INFO, "AAAA record"),
                                  ("NS", INFO, "NS record"), ("MX", INFO, "MX record")):
            vals = await R.query(r, host, rtype)
            records[rtype] = vals
            if vals:
                out.append(self.make(
                    ctx, title=f"{title} discovered",
                    severity=sev, description=f"{rtype} for {host}: {', '.join(vals[:8])}",
                    evidence=f"dig {host} {rtype} -> {vals}",
                    detection_method="Authoritative DNS query", confidence=CONFIRMED,
                    remediation="Maintain the zone and remove stale entries.",
                    tags=["dns", "inventory"]))
        if not records["A"] and not records["AAAA"]:
            out.append(self.make(
                ctx, title="Host does not resolve",
                severity=HIGH, cwe="CWE-1007",
                description="No A or AAAA record was returned for the target hostname.",
                evidence=f"A={records['A']} AAAA={records['AAAA']}",
                detection_method="DNS resolution", confidence=CONFIRMED,
                remediation="Verify the DNS zone.", tags=["dns"]))
        else:
            ns_vals = list(records.get("NS") or [])
            if not ns_vals:
                apex = await self._apex(r, host)
                ns_vals = await R.query(r, apex, "NS")
                records["NS"] = ns_vals
            topo = analyze_topology(
                ns_vals,
                records.get("A") or [],
                records.get("AAAA") or [],
                target_url=ctx.target.url,
                host=host,
            )
            ctx.topology = topo.classification
            ctx.origin_hidden = topo.origin_hidden
            ctx.scan_target = topo.scan_target
            ctx.resolved_ips = list((records.get("A") or []) + (records.get("AAAA") or []))
            out.extend(topo.findings)
        ctx.dns_records = records
        return records

    async def _mail_auth(self, r, ctx, host, records, out):
        apex = await self._apex(r, host)
        registrable = ctx.target.registrable.lower()
        txt = await R.query(r, apex, "TXT")
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        ctx.dns_records["TXT"] = txt

        # N4: MX priority 0 outside registrable domain or synthetic Cloudflare _dc-mx.*
        for raw_mx in records.get("MX") or []:
            prio, mx_host = parse_mx_entry(raw_mx)
            if not mx_host:
                continue
            if mx_host.startswith("_dc-mx.") or "._dc-mx." in mx_host:
                out.append(self.make(
                    ctx,
                    title="Cloudflare synthetic _dc-mx MX record exposes origin IP risk",
                    severity=LOW,
                    cwe="CWE-200",
                    description=(
                        f"MX points to Cloudflare synthetic record '{mx_host}', which resolves directly "
                        "to the unproxied mail/origin IP address."
                    ),
                    evidence=f"MX: {raw_mx}",
                    detection_method="MX record inspection",
                    confidence=CONFIRMED,
                    remediation="Host mail on a separate server IP from the web origin.",
                    tags=["dns", "email", "mx", "origin-exposure"],
                ))
            elif prio == 0 and not (mx_host == registrable or mx_host.endswith("." + registrable)):
                out.append(self.make(
                    ctx,
                    title="MX priority 0 points outside registrable domain",
                    severity=LOW,
                    cwe="CWE-200",
                    description=f"Primary MX (priority 0) routes mail to external domain '{mx_host}'.",
                    evidence=f"MX: {raw_mx} (registrable={registrable})",
                    detection_method="MX record inspection",
                    confidence=CONFIRMED,
                    remediation="Verify external mail provider authorization and SPF alignment.",
                    tags=["dns", "email", "mx"],
                ))

        # N6: Domain has no MX AND no SPF -> MEDIUM "Domain sends no mail, spoofable"
        if not records.get("MX") and not spf:
            out.append(self.make(
                ctx,
                title="Domain sends no mail, spoofable",
                severity=MEDIUM,
                cwe="CWE-290",
                description="The domain publishes neither MX nor SPF records, leaving it open to spoofed email.",
                evidence=f"MX={records.get('MX')} TXT={txt or '(empty)'}",
                detection_method="MX + SPF absence check",
                confidence=CONFIRMED,
                remediation="v=spf1 -all",
                tags=["dns", "email", "spoofing"],
            ))
        elif not spf:
            out.append(self.make(
                ctx, title="No SPF record published",
                severity=MEDIUM, cwe="CWE-290",
                description="Without SPF, receiving servers cannot verify which hosts may send "
                            "mail for this domain, easing sender spoofing.",
                evidence=f"dig {apex} TXT -> {txt or '(empty)'}",
                detection_method="TXT record query", confidence=CONFIRMED,
                remediation="Publish v=spf1 with explicit authorised senders and -all.",
                tags=["dns", "email", "spoofing"]))
        else:
            policy = spf[0]
            if policy.rstrip().endswith("~all"):
                out.append(self.make(
                    ctx, title="SPF uses soft-fail (~all)",
                    severity=LOW, cwe="CWE-290",
                    description="Soft-fail marks unauthorised senders but does not reject them.",
                    evidence=policy, detection_method="SPF policy parsing",
                    confidence=CONFIRMED, remediation="Move to -all once senders are confirmed.",
                    tags=["dns", "email"]))
            elif policy.rstrip().endswith("?all"):
                out.append(self.make(
                    ctx, title="SPF uses neutral (?all)",
                    severity=MEDIUM, cwe="CWE-290",
                    description="Neutral SPF asserts nothing about unauthorised senders.",
                    evidence=policy, detection_method="SPF policy parsing",
                    confidence=CONFIRMED, remediation="Replace ?all with -all.",
                    tags=["dns", "email"]))
            # N1: >1 v=spf1 TXT -> MEDIUM "Multiple SPF records, RFC 7208 invalid"
            if len(spf) > 1:
                out.append(self.make(
                    ctx, title="Multiple SPF records, RFC 7208 invalid",
                    severity=MEDIUM, cwe="CWE-290",
                    description="More than one v=spf1 record causes RFC 7208 permerror.",
                    evidence="\n".join(spf), detection_method="TXT record query",
                    confidence=CONFIRMED, remediation="Merge into a single SPF record.",
                    tags=["dns", "email"]))
            lookups = len(re.findall(r"\b(include|a|mx|ptr|exists|redirect)", policy, re.I))
            if lookups > 10:
                out.append(self.make(
                    ctx, title=f"SPF exceeds the 10-DNS-lookup limit ({lookups} mechanisms)",
                    severity=LOW, cwe="CWE-290",
                    description="Over-limit SPF yields permerror and can fail open.",
                    evidence=policy, detection_method="SPF mechanism count",
                    confidence=HIGH_CONF, remediation="Flatten includes below 10 lookups.",
                    tags=["dns", "email"]))

        dmarc = await R.query(r, f"_dmarc.{apex}", "TXT")
        dmarc_recs = [d for d in dmarc if d.strip().lower().startswith("v=dmarc1")]
        # N2: >1 v=DMARC1 TXT -> MEDIUM "Multiple DMARC records, second ignored"
        if len(dmarc_recs) > 1:
            out.append(self.make(
                ctx,
                title="Multiple DMARC records, second ignored",
                severity=MEDIUM,
                cwe="CWE-290",
                description="Multiple v=DMARC1 TXT records exist at _dmarc; RFC 7489 requires receivers to ignore DMARC or disregard additional records.",
                evidence="\n".join(dmarc_recs),
                detection_method="DMARC TXT record count",
                confidence=CONFIRMED,
                remediation="Publish exactly one v=DMARC1 TXT record at _dmarc.",
                tags=["dns", "email", "dmarc"],
            ))

        dmarc_rec = dmarc_recs[0] if dmarc_recs else ""
        if not dmarc_rec:
            out.append(self.make(
                ctx, title="No DMARC record published",
                severity=MEDIUM, cwe="CWE-290",
                description="Without DMARC, SPF/DKIM failures are not acted upon and no "
                            "reporting exists, so direct-domain spoofing stays viable.",
                evidence=f"dig _dmarc.{apex} TXT -> {dmarc or '(empty)'}",
                detection_method="DMARC record query", confidence=CONFIRMED,
                remediation="Publish v=DMARC1; p=none; rua=mailto:... then tighten to "
                            "quarantine/reject.", tags=["dns", "email", "spoofing"]))
        else:
            tags = parse_dmarc_tags(dmarc_rec)
            p_val = tags.get("p", "").lower()
            sp_val = tags.get("sp", "").lower()
            pct_raw = tags.get("pct", "100")
            try:
                pct_val = int(pct_raw)
            except ValueError:
                pct_val = 100

            if not p_val:
                out.append(self.make(
                    ctx, title="DMARC record has no policy (p=)",
                    severity=MEDIUM, cwe="CWE-290",
                    description="A DMARC record without p= is ineffective.",
                    evidence=dmarc_rec, detection_method="DMARC policy parsing",
                    confidence=CONFIRMED, remediation="Add p=quarantine or p=reject.",
                    tags=["dns", "email"]))
            elif p_val == "none":
                out.append(self.make(
                    ctx, title="DMARC policy is 'none' (monitor only)",
                    severity=LOW, cwe="CWE-290",
                    description="p=none collects reports but does not block spoofed mail.",
                    evidence=dmarc_rec, detection_method="DMARC policy parsing",
                    confidence=CONFIRMED, remediation="Advance to p=quarantine then p=reject.",
                    tags=["dns", "email"]))
            elif p_val == "quarantine" and pct_val < 100:
                out.append(self.make(
                    ctx,
                    title=f"DMARC quarantine policy applies to only {pct_val}% of messages (pct<100)",
                    severity=LOW,
                    cwe="CWE-290",
                    description=f"DMARC p=quarantine is configured with pct={pct_val}, leaving {100 - pct_val}% of failing mail unquarantined.",
                    evidence=dmarc_rec,
                    detection_method="DMARC policy parsing",
                    confidence=CONFIRMED,
                    remediation="Set pct=100 (or omit pct) and advance to p=reject.",
                    tags=["dns", "email", "dmarc"],
                ))

            if p_val == "reject" and sp_val == "none":
                out.append(self.make(
                    ctx,
                    title="DMARC subdomain policy (sp=none) weaker than domain policy (p=reject)",
                    severity=LOW,
                    cwe="CWE-290",
                    description="While the apex enforces p=reject, subdomains explicitly allow spoofed mail via sp=none.",
                    evidence=dmarc_rec,
                    detection_method="DMARC policy parsing",
                    confidence=CONFIRMED,
                    remediation="Set sp=reject or sp=quarantine to protect subdomains from spoofing.",
                    tags=["dns", "email", "dmarc"],
                ))

            # N3: DMARC rua=/ruf= pointing outside registrable domain
            rep_uris = ",".join(filter(None, [tags.get("rua", ""), tags.get("ruf", "")]))
            ext_doms = [
                d for d in extract_dmarc_report_domains(rep_uris)
                if d != registrable and not d.endswith("." + registrable)
            ]
            if ext_doms:
                out.append(self.make(
                    ctx,
                    title="DMARC reports go to third party",
                    severity=LOW,
                    cwe="CWE-200",
                    description=(
                        f"DMARC rua/ruf points to external domain(s) ({', '.join(ext_doms)}). "
                        f"Verify `{apex}._report._dmarc.<third-party>` TXT authorization."
                    ),
                    evidence=f"DMARC: {dmarc_rec}\nExternal report domain(s): {', '.join(ext_doms)}",
                    detection_method="DMARC rua/ruf domain inspection",
                    confidence=CONFIRMED,
                    remediation="Verify third-party DMARC processor authorization (`_report._dmarc` TXT record).",
                    tags=["dns", "email", "dmarc"],
                ))

        dkim_found = await self._dkim(r, apex, ctx.config)
        if dkim_found:
            out.append(self.make(
                ctx, title="DKIM selector discovered",
                severity=INFO,
                description=f"DKIM key published under selector '{dkim_found}'.",
                evidence=f"selector={dkim_found}",
                detection_method="Selector dictionary query", confidence=CONFIRMED,
                remediation="Rotate keys periodically.", tags=["dns", "email", "inventory"]))
        elif records["MX"]:
            out.append(self.make(
                ctx, title="No DKIM at common selectors (selector may differ)",
                severity=LOW, cwe="CWE-290",
                description="DKIM keys were not located for the 16 common selectors; a custom "
                            "selector may be in use.",
                evidence=f"selectors tried: {list(COMMON_DKIM_SELECTORS)}",
                detection_method="Selector dictionary query", confidence=NEEDS_MANUAL,
                remediation="Confirm selector names with the mail operator.", tags=["dns", "email"]))

    async def _dkim(self, r, apex: str, config) -> str | None:
        cfg_sels = list(config.get("dns.dkim_selectors", []) or [])
        selectors = list(dict.fromkeys(list(COMMON_DKIM_SELECTORS) + cfg_sels))
        tasks = [R.query(r, f"{s}._domainkey.{apex}", "TXT") for s in selectors]
        for selector, values in zip(selectors, await asyncio.gather(*tasks, return_exceptions=True)):
            if isinstance(values, list) and any("p=" in v for v in values):
                return selector
        return None

    async def _dnssec(self, r, ctx, host, out):
        apex = await self._apex(r, host)
        dnskey = await R.query(r, apex, "DNSKEY")
        ds = await R.query(r, apex, "DS")
        out.extend(evaluate_dnssec(dnskey, ds, apex=apex, target_url=ctx.target.url))

    async def _caa(self, r, ctx, host, out):
        apex = await self._apex(r, host)
        caa = await R.query(r, apex, "CAA")
        out.extend(evaluate_caa(caa, apex=apex, target_url=ctx.target.url))

    async def _dangling(self, r, ctx, host, out):
        chain = await R.resolve_chain(r, host)
        if not chain:
            return
        final = chain[-1]
        match = next((svc for svc in TAKEOVER_FINGERPRINTS if final.endswith(svc)), None)
        if not match:
            return
        marker = TAKEOVER_FINGERPRINTS[match]
        resp = await ctx.http.request("GET", ctx.target.url, retry=False)
        body = resp.body if resp.ok else ""
        unclaimed = marker.lower() in body.lower() or (resp.ok and resp.status == 404)
        out.append(self.make(
            ctx, title=f"Possible subdomain takeover (CNAME to {match})",
            severity=CRITICAL if unclaimed else MEDIUM, cwe="CWE-350",
            description=("The CNAME chain points at a third-party service and the response "
                         "matches that provider's 'unclaimed' marker. An attacker could "
                         "register the name and serve content on the victim domain."
                         if unclaimed else
                         "The CNAME chain points at a third-party service; the response did "
                         "not show a definitive unclaimed marker."),
            evidence=(f"CNAME chain: {' -> '.join([host] + chain)}\n"
                      f"Provider marker: '{marker}'\n"
                      f"Marker observed in body: {unclaimed}\n"
                      f"HTTP {resp.status}"),
            detection_method="CNAME chain + provider fingerprint",
            confidence=HIGH_CONF if unclaimed else NEEDS_MANUAL,
            remediation="Reclaim the name at the provider or remove the dangling CNAME.",
            tags=["dns", "takeover"]))

    async def _subdomains(self, r, ctx, host, out):
        apex = await self._apex(r, host)
        # M1: Resolve 2 random 8-char labels under apex before brute-forcing
        lbl1 = f"wc{secrets.token_hex(3)}.{apex}"
        lbl2 = f"wc{secrets.token_hex(3)}.{apex}"
        p1, p2 = await asyncio.gather(R.query(r, lbl1, "A"), R.query(r, lbl2, "A"), return_exceptions=True)
        ips1 = p1 if isinstance(p1, list) else []
        ips2 = p2 if isinstance(p2, list) else []
        is_wc, bf_enabled, wc_ips, wc_findings = evaluate_wildcard_dns(
            ips1, ips2, target_url=ctx.target.url, apex=apex
        )
        ctx.wildcard_dns = is_wc
        ctx.brute_force_enabled = bf_enabled
        if is_wc:
            out.extend(wc_findings)
            ctx.subdomains = []
            return

        words = ctx.config.get("dns.subdomain_wordlist", [])[:30]
        candidates: list[str] = []
        for w in words:
            c = canonicalize_subdomain(f"{w}.{apex}", apex=apex)
            if c and c not in candidates:
                candidates.append(c)
        tasks = {c: R.query(r, c, "A") for c in candidates}
        raw_hits: list[tuple[str, list[str]]] = []
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, res in zip(tasks.keys(), results):
            if isinstance(res, list) and res:
                raw_hits.append((name, res))
        deduped = dedupe_subdomains(raw_hits, apex=apex)
        found = [f"{canon} -> {', '.join(ips)}" for canon, ips in deduped]
        ctx.subdomains = [canon for canon, _ in deduped]
        if found:
            out.append(self.make(
                ctx, title=f"{len(found)} subdomain(s) discovered passively",
                severity=INFO,
                description="Passive dictionary resolution against the apex. Expand manually "
                            "for full inventory.",
                evidence="\n".join(found[:40]),
                detection_method="DNS dictionary brute-force", confidence=CONFIRMED,
                remediation="Review each for authentication and patching coverage.",
                tags=["dns", "discovery"]))

    @staticmethod
    async def _apex(r, host: str) -> str:
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        for i in range(1, len(parts) - 1):
            candidate = ".".join(parts[i:])
            if await R.query(r, candidate, "SOA"):
                return candidate
        return ".".join(parts[-2:])