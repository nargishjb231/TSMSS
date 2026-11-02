"""DNS posture: records, mail auth, DNSSEC, CAA, passive discovery, dangling DNS."""
from __future__ import annotations

import asyncio
import re

from core import resolver as R
from core.finding import CONFIRMED, HIGH_CONF, CRITICAL, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
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
        ctx.dns_records = records
        return records

    async def _mail_auth(self, r, ctx, host, records, out):
        apex = await self._apex(r, host)
        txt = await R.query(r, apex, "TXT")
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        ctx.dns_records["TXT"] = txt

        if not records["MX"] and not spf:
            return
        if not spf:
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
            if len(spf) > 1:
                out.append(self.make(
                    ctx, title="Multiple SPF records published",
                    severity=MEDIUM, cwe="CWE-290",
                    description="More than one v=spf1 record breaks evaluation per RFC 7208.",
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
        dmarc_rec = next((d for d in dmarc if d.lower().startswith("v=dmarc1")), "")
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
            pol = re.search(r"\bp\s*=\s*(\w+)", dmarc_rec, re.I)
            value = (pol.group(1).lower() if pol else "")
            if value == "none":
                out.append(self.make(
                    ctx, title="DMARC policy is 'none' (monitor only)",
                    severity=LOW, cwe="CWE-290",
                    description="p=none collects reports but does not block spoofed mail.",
                    evidence=dmarc_rec, detection_method="DMARC policy parsing",
                    confidence=CONFIRMED, remediation="Advance to p=quarantine then p=reject.",
                    tags=["dns", "email"]))
            elif not pol:
                out.append(self.make(
                    ctx, title="DMARC record has no policy (p=)",
                    severity=MEDIUM, cwe="CWE-290",
                    description="A DMARC record without p= is ineffective.",
                    evidence=dmarc_rec, detection_method="DMARC policy parsing",
                    confidence=CONFIRMED, remediation="Add p=quarantine or p=reject.",
                    tags=["dns", "email"]))

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
                ctx, title="No DKIM key found under common selectors",
                severity=INFO, cwe="CWE-290",
                description="DKIM keys were not located for the common selectors; a custom "
                            "selector may be in use.",
                evidence=f"selectors tried: {ctx.config.get('dns.dkim_selectors')}",
                detection_method="Selector dictionary query", confidence=NEEDS_MANUAL,
                remediation="Confirm selector names with the mail operator.", tags=["dns", "email"]))

    async def _dkim(self, r, apex: str, config) -> str | None:
        selectors = config.get("dns.dkim_selectors", [])[:10]
        tasks = [R.query(r, f"{s}._domainkey.{apex}", "TXT") for s in selectors]
        for selector, values in zip(selectors, await asyncio.gather(*tasks, return_exceptions=True)):
            if isinstance(values, list) and any("p=" in v for v in values):
                return selector
        return None

    async def _dnssec(self, r, ctx, host, out):
        apex = await self._apex(r, host)
        dnskey = await R.query(r, apex, "DNSKEY")
        ds = await R.query(r, apex, "DS")
        if not dnskey:
            out.append(self.make(
                ctx, title="DNSSEC not enabled (no DNSKEY)",
                severity=LOW, cwe="CWE-350",
                description="Without DNSSEC, forged DNS answers cannot be cryptographically "
                            "detected by validating resolvers.",
                evidence=f"dig {apex} DNSKEY -> (empty)",
                detection_method="DNSKEY query", confidence=CONFIRMED,
                remediation="Sign the zone and publish DS at the registrar.",
                tags=["dns", "dnssec"]))
        else:
            out.append(self.make(
                ctx, title="DNSSEC signing keys present",
                severity=INFO,
                description="The zone publishes DNSKEY records; validation depends on a DS "
                            "record existing in the parent zone.",
                evidence=f"DNSKEY count={len(dnskey)} DS count={len(ds)}",
                detection_method="DNSKEY/DS query", confidence=CONFIRMED,
                remediation="Monitor signature expiry and key rollover.",
                tags=["dns", "dnssec"]))
            if not ds:
                out.append(self.make(
                    ctx, title="DNSKEY present but no DS in parent zone",
                    severity=MEDIUM, cwe="CWE-350",
                    description="Without a DS record the chain of trust is incomplete and "
                            "validating resolvers treat the zone as unsigned.",
                    evidence=f"dig {apex} DS -> (empty)",
                    detection_method="DS query", confidence=HIGH_CONF,
                    remediation="Submit the DS record to the registrar.",
                    tags=["dns", "dnssec"]))

    async def _caa(self, r, ctx, host, out):
        apex = await self._apex(r, host)
        caa = await R.query(r, apex, "CAA")
        if not caa:
            out.append(self.make(
                ctx, title="No CAA record restricts certificate issuance",
                severity=LOW, cwe="CWE-295",
                description="Any public CA may issue for this domain, widening the blast "
                            "radius of a mis-issuance.",
                evidence=f"dig {apex} CAA -> (empty)",
                detection_method="CAA query", confidence=CONFIRMED,
                remediation="Publish CAA authorising only the CAs in use, plus iodef.",
                tags=["dns", "caa"]))
        else:
            out.append(self.make(
                ctx, title="CAA policy published",
                severity=INFO, description=f"CAA: {'; '.join(caa[:5])}",
                evidence="\n".join(caa), detection_method="CAA query",
                confidence=CONFIRMED, remediation="Review the authorised CA list.",
                tags=["dns", "caa"]))

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