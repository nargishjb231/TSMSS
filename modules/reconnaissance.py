"""Passive reconnaissance, endpoint inventory, robots/sitemap/security.txt, and client-side DOM/storage analysis."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from core.finding import CONFIRMED, HIGH_CONF, INFO, LOW, MEDIUM, NEEDS_MANUAL, POTENTIAL, STRONG_EVIDENCE
from modules.base import BaseModule

SENSITIVE_ROBOTS = re.compile(
    r"(?i)/(admin|backup|bak|config|db|debug|dump|env|git|graphql|internal|private|secret|staging|swagger|test)"
)
STANDARD_CMS_ROBOTS = re.compile(
    r"(?i)^/(wp-admin|wp-content|wp-includes|wp-json)(/|$|\*)"
)


def is_standard_cms_robots_entry(path: str) -> bool:
    """J5: Return True if *path* is a standard WordPress/CMS robots.txt disallow entry."""
    return bool(STANDARD_CMS_ROBOTS.match((path or "").strip()))
DOM_SINKS = re.compile(r"\b(innerHTML|outerHTML|document\.write|document\.writeln|eval|setTimeout\s*\(\s*['\"])\b")
DOM_SOURCES = re.compile(r"\b(location\.search|location\.hash|location\.href|document\.URL|document\.referrer|window\.name|addEventListener\s*\(\s*['\"]message['\"])\b")
STORAGE_TOKEN_SINK = re.compile(
    r"(?i)\b(localStorage|sessionStorage)\.setItem\s*\(\s*['\"]([^'\"]*(?:token|jwt|auth|secret|api[_-]?key|session)[^'\"]*)['\"]"
)
FRONTEND_CONFIG_LEAK = re.compile(
    r"(?i)\b(NEXT_PUBLIC_[A-Z0-9_]*SECRET[A-Z0-9_]*|REACT_APP_[A-Z0-9_]*SECRET[A-Z0-9_]*|firebaseConfig\s*=\s*\{[^}]{20,300}\})"
)


class ReconnaissanceModule(BaseModule):
    name = "reconnaissance"
    category = "Reconnaissance"

    async def run(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        out = []
        out += await self._robots_and_sitemap(ctx)
        out += self._endpoint_and_upload_inventory(ctx, resp)
        out += await self._client_side_and_sourcemaps(ctx, resp)
        return out

    async def _robots_and_sitemap(self, ctx):
        out = []
        base = str(ctx.target.root).rstrip("/")

        # 1. robots.txt (WSTG-INFO-03)
        r_url = f"{base}/robots.txt"
        r_resp = await ctx.http.request("GET", r_url, retry=False)
        if r_resp.ok and r_resp.status == 200 and "<html" not in r_resp.body[:300].lower():
            disallows = []
            sitemaps = []
            for raw_line in r_resp.body.splitlines()[:200]:
                line = raw_line.split("#", 1)[0].strip()
                if line.lower().startswith("disallow:"):
                    val = line.split(":", 1)[1].strip()
                    if val and val != "/":
                        disallows.append(val)
                elif line.lower().startswith("sitemap:"):
                    sitemaps.append(line.split(":", 1)[1].strip())
            non_cms = [d for d in disallows if not is_standard_cms_robots_entry(d)]
            sensitive = [d for d in non_cms if SENSITIVE_ROBOTS.search(d)]
            if sensitive:
                out.append(self.make(
                    ctx,
                    title="robots.txt discloses sensitive path patterns",
                    severity=LOW,
                    cwe="CWE-200",
                    description=f"robots.txt lists {len(sensitive)} potentially sensitive disallowed path(s).",
                    evidence=f"GET {r_url} -> 200\nDisallowed: {', '.join(sensitive[:12])}",
                    detection_method="Passive robots.txt inspection",
                    confidence=CONFIRMED,
                    url=r_url,
                    remediation="Do not rely on robots.txt to hide sensitive administrative or backup routes; enforce authentication and access controls.",
                    tags=["recon", "robots", "wstg-info-03"],
                ))
            elif disallows or sitemaps:
                out.append(self.make(
                    ctx,
                    title="robots.txt indexed",
                    severity=INFO,
                    cwe="CWE-200",
                    description=f"robots.txt contains {len(disallows)} disallow rule(s) and {len(sitemaps)} sitemap reference(s).",
                    evidence=f"GET {r_url} -> 200\nSample: {', '.join((disallows + sitemaps)[:8])}",
                    detection_method="Passive robots.txt inspection",
                    confidence=CONFIRMED,
                    url=r_url,
                    remediation="Informational inventory; ensure disallowed routes still enforce server-side authorization.",
                    tags=["recon", "robots"],
                ))

        # 2. sitemap.xml (WSTG-INFO-03)
        s_url = f"{base}/sitemap.xml"
        s_resp = await ctx.http.request("GET", s_url, retry=False)
        if s_resp.ok and s_resp.status == 200 and ("<urlset" in s_resp.body[:600] or "<sitemapindex" in s_resp.body[:600]):
            locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", s_resp.body[:50000], re.I)
            if locs:
                out.append(self.make(
                    ctx,
                    title="Public sitemap.xml endpoint inventory discovered",
                    severity=INFO,
                    cwe="CWE-200",
                    description=f"sitemap.xml enumerates {len(locs)} public URL(s).",
                    evidence=f"GET {s_url} -> 200\nSample URLs: {', '.join(locs[:6])}",
                    detection_method="Passive sitemap.xml parsing",
                    confidence=CONFIRMED,
                    url=s_url,
                    remediation="Ensure only intended public routes are listed in sitemap.xml.",
                    tags=["recon", "sitemap"],
                ))

        return out

    def _endpoint_and_upload_inventory(self, ctx, resp):
        out = []
        soup = BeautifulSoup(resp.body, "html.parser")

        # File upload configuration check (Section 6F — WSTG-BUSL-08 / WSTG-BUSL-09)
        file_inputs = soup.find_all("input", attrs={"type": re.compile(r"^file$", re.I)})
        for finp in file_inputs[:3]:
            accept = (finp.get("accept") or "").strip()
            name = finp.get("name") or finp.get("id") or "file"
            if not accept:
                out.append(self.make(
                    ctx,
                    title=f"File upload input '{name}' lacks client-side accept restriction",
                    severity=LOW,
                    cwe="CWE-434",
                    description="An HTML file upload control does not specify an 'accept' MIME/extension attribute. Server-side validation must be verified manually.",
                    evidence=str(finp)[:200],
                    detection_method="Static form inspection",
                    confidence=POTENTIAL,
                    parameter=str(name),
                    remediation="Enforce strict server-side content-type, magic-byte, and extension allowlists, and store uploads outside the web root.",
                    tags=["recon", "upload", "business-logic"],
                ))

        # Subresource Integrity (SRI) check on external scripts (Section 6B/6F/6G — CWE-353)
        ext_scripts_without_sri = []
        target_host = (ctx.target.host or "").lower()
        for scr in soup.find_all("script", src=True):
            src = (scr.get("src") or "").strip()
            if not src.startswith(("http://", "https://", "//")):
                continue
            full_src = urljoin(ctx.target.url, src)
            shost = (urlsplit(full_src).hostname or "").lower()
            if shost and shost != target_host and not shost.endswith("." + target_host):
                if not scr.get("integrity"):
                    ext_scripts_without_sri.append(full_src)
        if ext_scripts_without_sri:
            out.append(self.make(
                ctx,
                title="External scripts loaded without Subresource Integrity (SRI)",
                severity=LOW,
                cwe="CWE-353",
                description=f"{len(ext_scripts_without_sri)} third-party script(s) lack an 'integrity' attribute.",
                evidence="Sample: " + ", ".join(ext_scripts_without_sri[:4]),
                detection_method="HTML script tag inspection",
                confidence=CONFIRMED,
                remediation="Add 'integrity=\"sha384-...\"' and 'crossorigin=\"anonymous\"' to external CDN script tags.",
                tags=["recon", "sri", "client-side"],
            ))
        return out

    async def _client_side_and_sourcemaps(self, ctx, resp):
        out = []
        body = resp.body or ""

        # Check DOM XSS source + sink co-occurrence (Section 6E / 6G — WSTG-CLNT-01)
        sinks = set(DOM_SINKS.findall(body))
        sources = set(DOM_SOURCES.findall(body))
        if sinks and sources:
            out.append(self.make(
                ctx,
                title="Client-side DOM sources and dangerous sinks present in page script",
                severity=LOW,
                cwe="CWE-79",
                description=(
                    f"Page scripts reference DOM source(s) ({', '.join( sorted(sources)[:4] )}) "
                    f"and sink(s) ({', '.join( sorted(sinks)[:4] )}). Manual data-flow review is required to confirm DOM XSS."
                ),
                evidence=f"Sources: {sorted(sources)[:4]} | Sinks: {sorted(sinks)[:4]}",
                detection_method="Static JavaScript sink/source inspection",
                confidence=NEEDS_MANUAL,
                remediation="Use safe DOM APIs (textContent, setAttribute) or sanitize untrusted data with DOMPurify before writing to HTML sinks.",
                tags=["recon", "dom-xss", "client-side"],
            ))

        # Check browser storage risk indicators (Section 6G — WSTG-CLNT-12)
        storage_hits = STORAGE_TOKEN_SINK.findall(body)
        if storage_hits:
            formatted = [f"{store}.{key}" for store, key in storage_hits[:4]]
            out.append(self.make(
                ctx,
                title="Sensitive token key written to browser Web Storage",
                severity=LOW,
                cwe="CWE-922",
                description="JavaScript stores authentication or session token material in localStorage/sessionStorage, which is accessible to any XSS script.",
                evidence="Matched storage keys: " + ", ".join(formatted),
                detection_method="Static JavaScript storage analysis",
                confidence=STRONG_EVIDENCE,
                remediation="Store session tokens in HttpOnly, Secure, SameSite cookies rather than Web Storage.",
                tags=["recon", "storage", "client-side"],
            ))

        # Check exposed frontend configuration secrets
        cfg_match = FRONTEND_CONFIG_LEAK.search(body)
        if cfg_match:
            out.append(self.make(
                ctx,
                title="Sensitive frontend configuration variable exposed in client bundle",
                severity=MEDIUM,
                cwe="CWE-200",
                description="Client-visible JavaScript contains a secret-named environment variable or embedded configuration block.",
                evidence=cfg_match.group(0)[:160],
                detection_method="Static frontend configuration regex",
                confidence=HIGH_CONF,
                remediation="Move secret keys to server-side environment variables and never prefix private keys with NEXT_PUBLIC_ or REACT_APP_.",
                tags=["recon", "client-side", "disclosure"],
            ))

        # Check up to 2 same-origin JS files for exposed .js.map source maps (Section 6G)
        soup = BeautifulSoup(body, "html.parser")
        target_host = (ctx.target.host or "").lower()
        checked = 0
        for scr in soup.find_all("script", src=True):
            if checked >= 2:
                break
            src = (scr.get("src") or "").strip()
            if not src or ".js" not in src.lower():
                continue
            js_url = urljoin(ctx.target.url, src)
            if (urlsplit(js_url).hostname or "").lower() != target_host:
                continue
            map_url = js_url.split("?", 1)[0] + ".map"
            checked += 1
            m_resp = await ctx.http.request("GET", map_url, retry=False)
            if m_resp.ok and m_resp.status == 200 and m_resp.body.lstrip().startswith("{"):
                try:
                    data = json.loads(m_resp.body[:200_000])
                except Exception:
                    continue
                if isinstance(data, dict) and "mappings" in data and "sources" in data:
                    srcs = data.get("sources") or []
                    out.append(self.make(
                        ctx,
                        title=f"JavaScript source map exposed ({urlsplit(map_url).path})",
                        severity=LOW,
                        cwe="CWE-540",
                        description=f"Production source map is publicly downloadable, exposing {len(srcs)} original source file path(s).",
                        evidence=f"GET {map_url} -> 200\nSources sample: {', '.join(str(s) for s in srcs[:6])}",
                        detection_method="Source map (.js.map) verification",
                        confidence=CONFIRMED,
                        url=map_url,
                        remediation="Disable production source map publishing or restrict .map files to internal symbol servers.",
                        tags=["recon", "sourcemap", "client-side"],
                    ))
        return out
