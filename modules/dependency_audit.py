"""Dependency and version disclosure with known-risk mapping."""
from __future__ import annotations

import json
import re

from core.finding import CONFIRMED, HIGH_CONF, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule

# (regex, product, vulnerable-below, note)
RISK_TABLE = [
    (r'jquery[/-]?v?["\']?(\d+\.\d+\.\d+)', "jQuery", (3, 5, 0), "CVE-2020-11022/11023 (XSS)"),
    (r'bootstrap[/-]?v?["\']?(\d+\.\d+\.\d+)', "Bootstrap", (3, 4, 1), "CVE-2019-8331 (XSS)"),
    (r'angular(?:\.min)?\.js[/-]?v?["\']?(\d+\.\d+\.\d+)', "AngularJS", (1, 8, 0), "EOL, multiple XSS"),
    (r'lodash[/-]?v?["\']?(\d+\.\d+\.\d+)', "lodash", (4, 17, 21), "CVE-2021-23337"),
    (r'moment[/-]?v?["\']?(\d+\.\d+\.\d+)', "Moment.js", (2, 29, 4), "CVE-2022-31129"),
]


def _parse(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)


class DependencyAuditModule(BaseModule):
    name = "dependency_audit"
    category = "Framework Auditing"

    async def run(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        out = []
        out += self._frontend(ctx, resp)
        out += await self._manifests(ctx)
        return out

    def _frontend(self, ctx, resp):
        out = []
        for pattern, product, floor, note in RISK_TABLE:
            m = re.search(pattern, resp.body, re.I)
            if not m:
                continue
            version = m.group(1)
            sev, label = INFO, "current"
            if _parse(version) < floor:
                sev, label = MEDIUM, f"below {'.'.join(map(str, floor))}"
            out.append(self.make(
                ctx, title=f"{product} {version} referenced ({label})",
                severity=sev, cwe="CWE-1104",
                description=f"Client-side {product} version {version} was found in the page "
                            f"source. Known-risk baseline: {note}. Presence does not prove the "
                            "vulnerable code path is reachable.",
                evidence=f"matched: {m.group(0)[:120]}",
                detection_method="Source regex", confidence=HIGH_CONF if sev != INFO else CONFIRMED,
                remediation=f"Upgrade {product} to at least {'.'.join(map(str, floor))} or latest.",
                tags=["dependency", product.lower()]))
        return out

    async def _manifests(self, ctx):
        out = []
        for path, label in (("/package.json", "Node"), ("/composer.json", "PHP"),
                            ("/composer.lock", "PHP lock"), ("/package-lock.json", "Node lock")):
            url = str(ctx.target.root).rstrip("/") + path
            resp = await ctx.http.request("GET", url, retry=False)
            if not resp.ok or resp.status != 200 or "{" not in resp.body[:200]:
                continue
            try:
                data = json.loads(resp.body[:400_000])
            except (json.JSONDecodeError, ValueError):
                continue
            deps = {}
            for key in ("dependencies", "devDependencies", "require", "require-dev"):
                if isinstance(data.get(key), dict):
                    deps.update(data[key])
            if not deps:
                continue
            out.append(self.make(
                ctx, title=f"{label} dependency manifest exposed ({path})",
                severity=MEDIUM, cwe="CWE-200",
                description=f"{len(deps)} declared dependencies are readable, giving an exact "
                            "supply-chain map for CVE matching.",
                evidence=f"GET {url} -> 200\n" + ", ".join(sorted(deps)[:25]),
                detection_method="Manifest probe", confidence=CONFIRMED,
                remediation=f"Block or relocate {path} outside the document root.",
                tags=["dependency", "disclosure"]))
        return out