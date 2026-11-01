"""Infrastructure inventory: nmap connect scan, whois, CDN and cloud hints."""
from __future__ import annotations

import asyncio
import re
import shutil
import subprocess

from core.finding import CONFIRMED, HIGH_CONF, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule

CDN_SIGNS = {
    "cloudflare": ("cloudflare", "cf-ray", "__cfduid", "cf-cache-status"),
    "akamai": ("akamai", "akamaighost", "x-akamai"),
    "fastly": ("fastly", "x-served-by", "x-fastly"),
    "cloudfront": ("cloudfront", "x-amz-cf-id"),
    "azure-front-door": ("azurefd", "x-azure-ref"),
    "google": ("google frontend", "gws", "1e100.net"),
    "incapsula": ("incap_ses", "visid_incap", "x-iinfo"),
    "sucuri": ("sucuri", "x-sucuri-id"),
}

CLOUD_BUCKET_RE = re.compile(
    r"https?://([a-z0-9.\-]+)\.(s3[.-][a-z0-9\-]+\.amazonaws\.com|blob\.core\.windows\.net"
    r"|storage\.googleapis\.com)", re.I)


class InfrastructureModule(BaseModule):
    name = "infrastructure"
    category = "Infrastructure"

    async def run(self, ctx):
        out = []
        resp = getattr(ctx, "homepage", None)
        if resp is not None:
            out += self._cdn(ctx, resp)
            out += self._cloud_refs(ctx, resp)
        if ctx.config.get("infra.enable_nmap", True):
            out += await self._nmap(ctx)
        if ctx.config.get("infra.enable_whois", True):
            out += await self._whois(ctx)
        return out

    def _cdn(self, ctx, resp):
        blob = (resp.body[:200_000] + " " + " ".join(f"{k}:{v}" for k, v in resp.headers.items())).lower()
        for name, sigs in CDN_SIGNS.items():
            if any(s in blob for s in sigs):
                ctx.cdn = name
                return [self.make(
                    ctx, title=f"CDN / edge provider identified: {name}",
                    severity=INFO,
                    description="Traffic appears to be fronted by a CDN. Edge caching and WAF "
                                "behaviour affect findings; origin-direct checks may differ.",
                    evidence=f"matched signature for {name}",
                    detection_method="Response signature matching", confidence=HIGH_CONF,
                    remediation="Confirm edge and origin configurations are both hardened.",
                    tags=["infrastructure", "cdn"])]
        return []

    def _cloud_refs(self, ctx, resp):
        found = set(CLOUD_BUCKET_RE.findall(resp.body[:200_000]))
        out = []
        for bucket, domain in list(found)[:5]:
            out.append(self.make(
                ctx, title=f"Cloud storage reference in page source ({domain.split('.')[0]})",
                severity=INFO,
                description="The page references object storage. Confirm listing permissions.",
                evidence=f"{bucket}.{domain}",
                detection_method="Source regex scan", confidence=HIGH_CONF,
                remediation="Verify bucket ACLs and disable public listing if unused.",
                tags=["infrastructure", "cloud"]))
        return out

    async def _nmap(self, ctx):
        if not shutil.which("nmap"):
            return []
        ports = ctx.config.get("infra.nmap_ports", "80,443")
        timeout = ctx.config.get("infra.nmap_host_timeout", "90s")
        cmd = ["nmap", "-sT", "--unprivileged", "-Pn", "-n", "--open",
               "-p", ports, "--host-timeout", timeout, ctx.target.host]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            raw, _ = await asyncio.wait_for(proc.communicate(), timeout=150)
        except (asyncio.TimeoutError, OSError) as exc:
            return [self.make(
                ctx, title="nmap connect scan did not complete",
                severity=INFO, description=f"{type(exc).__name__}",
                evidence=" ".join(cmd), detection_method="nmap -sT",
                confidence=NEEDS_MANUAL, remediation="Re-run manually if required.",
                tags=["infrastructure", "nmap"])]
        text = raw.decode("utf-8", "replace")
        open_ports = re.findall(r"^(\d+)/tcp\s+open\s+(\S+)", text, re.M)
        out = []
        for port, service in open_ports:
            sev = MEDIUM if port not in ("80", "443") else INFO
            out.append(self.make(
                ctx, title=f"Open port {port}/tcp ({service})",
                severity=sev,
                description="A reachable TCP service was identified on a non-standard or "
                            "standard port.",
                evidence=text[-1500:], detection_method="nmap connect scan",
                confidence=CONFIRMED,
                remediation="Restrict non-public services at the firewall.",
                tags=["infrastructure", "ports"]))
        ctx.open_ports = [int(p) for p, _ in open_ports]
        if not open_ports:
            out.append(self.make(
                ctx, title="No open ports found in the scanned set",
                severity=INFO,
                description=f"Ports probed: {ports}",
                evidence=text[-600:], detection_method="nmap connect scan",
                confidence=CONFIRMED, remediation="Expand the port list if needed.",
                tags=["infrastructure", "ports"]))
        return out

    async def _whois(self, ctx):
        if not shutil.which("whois"):
            return []
        try:
            proc = await asyncio.create_subprocess_exec(
                "whois", ctx.target.host, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL)
            raw, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        except (asyncio.TimeoutError, OSError):
            return []
        text = raw.decode("utf-8", "replace")
        if not text.strip():
            return []
        out = []
        created = re.search(r"(?im)^(?:creation date|created|registered on)\s*:\s*(.+)$", text)
        expiry = re.search(r"(?im)^(?:expiry date|expiration date|paid-till)\s*:\s*(.+)$", text)
        registrar = re.search(r"(?im)^registrar\s*:\s*(.+)$", text)
        if expiry:
            out.append(self.make(
                ctx, title="Domain registration expiry on record",
                severity=INFO,
                description=f"Expiry: {expiry.group(1).strip()}",
                evidence=text[:800], detection_method="whois", confidence=HIGH_CONF,
                remediation="Enable registrar lock and auto-renew.",
                tags=["infrastructure", "whois"]))
        if registrar:
            out.append(self.make(
                ctx, title="Domain registrar identified",
                severity=INFO, description=registrar.group(1).strip(),
                evidence=text[:800], detection_method="whois", confidence=HIGH_CONF,
                remediation="Confirm registrar lock and MFA on the account.",
                tags=["infrastructure", "whois"]))
        if created:
            out.append(self.make(
                ctx, title="Domain creation date on record",
                severity=INFO, description=created.group(1).strip(),
                evidence=text[:400], detection_method="whois", confidence=HIGH_CONF,
                remediation="Young domains warrant extra scrutiny.", tags=["infrastructure"]))
        return out