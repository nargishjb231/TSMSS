"""Dependency and version disclosure with known-risk mapping (HTTP & local lockfiles)."""
from __future__ import annotations

import json
from pathlib import Path
import re

from core.finding import CONFIRMED, Finding, HIGH, HIGH_CONF, INFO, LOW, MEDIUM, NEEDS_MANUAL, POTENTIAL
from modules.base import BaseModule

# (regex, product, vulnerable-below, note)
RISK_TABLE = [
    (r'jquery[/-]?v?["\']?(\d+\.\d+\.\d+)', "jQuery", (3, 5, 0), "CVE-2020-11022/11023 (XSS)"),
    (r'bootstrap[/-]?v?["\']?(\d+\.\d+\.\d+)', "Bootstrap", (3, 4, 1), "CVE-2019-8331 (XSS)"),
    (r'angular(?:\.min)?\.js[/-]?v?["\']?(\d+\.\d+\.\d+)', "AngularJS", (1, 8, 0), "EOL, multiple XSS"),
    (r'lodash[/-]?v?["\']?(\d+\.\d+\.\d+)', "lodash", (4, 17, 21), "CVE-2021-23337"),
    (r'moment[/-]?v?["\']?(\d+\.\d+\.\d+)', "Moment.js", (2, 29, 4), "CVE-2022-31129"),
    (r'dompurify[/-]?v?["\']?(\d+\.\d+\.\d+)', "DOMPurify", (2, 4, 0), "CVE-2022-25892 (mXSS)"),
    (r'handlebars(?:\.min)?\.js[/-]?v?["\']?(\d+\.\d+\.\d+)', "Handlebars", (4, 7, 7), "CVE-2021-23369 (RCE/Prototype Pollution)"),
]

# Offline advisory catalog for local manifest/lockfile auditing:
# pkg_lower -> (ecosystem, floor_tuple, cve_id, severity, summary)
LOCAL_PACKAGE_ADVISORIES: dict[str, tuple[str, tuple[int, ...], str, str, str]] = {
    "django": ("PyPI", (4, 2, 11), "CVE-2024-27351", HIGH, "Regular expression DoS and security fixes in Django < 4.2.11"),
    "flask": ("PyPI", (2, 2, 5), "CVE-2023-30861", HIGH, "Session cookie disclosure on caching proxies in Flask < 2.2.5"),
    "requests": ("PyPI", (2, 31, 0), "CVE-2023-32681", MEDIUM, "Proxy-Authorization header leak on cross-origin redirect"),
    "urllib3": ("PyPI", (2, 0, 7), "CVE-2023-45803", MEDIUM, "Request body not stripped on redirect after 303"),
    "pyyaml": ("PyPI", (5, 4, 0), "CVE-2020-14343", CRITICAL_SEV := "CRITICAL", "Arbitrary code execution via full_load in PyYAML < 5.4"),
    "cryptography": ("PyPI", (42, 0, 4), "CVE-2024-26130", HIGH, "NULL pointer dereference in PKCS12 parsing"),
    "jinja2": ("PyPI", (3, 1, 4), "CVE-2024-34064", MEDIUM, "HTML attribute injection via xmlattr filter"),
    "pillow": ("PyPI", (10, 3, 0), "CVE-2024-28219", HIGH, "Buffer overflow in _imagingcms.c"),
    "werkzeug": ("PyPI", (3, 0, 3), "CVE-2024-34069", HIGH, "Debugger RCE / cross-origin request risk"),
    "aiohttp": ("PyPI", (3, 9, 4), "CVE-2024-23334", HIGH, "Path traversal in static file handling"),
    "express": ("npm", (4, 19, 2), "CVE-2024-29041", MEDIUM, "Open redirect via malformed URL in Express < 4.19.2"),
    "axios": ("npm", (1, 6, 0), "CVE-2023-45857", MEDIUM, "XSRF-TOKEN header leakage to third-party hosts"),
    "lodash": ("npm", (4, 17, 21), "CVE-2021-23337", HIGH, "Command injection via template function"),
    "jsonwebtoken": ("npm", (9, 0, 0), "CVE-2022-23529", HIGH, "Insecure key retrieval in jsonwebtoken < 9.0.0"),
    "minimist": ("npm", (1, 2, 6), "CVE-2021-44906", HIGH, "Prototype pollution in minimist < 1.2.6"),
}


def _parse(v: str) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", v or "")[:3]]
    return tuple(nums) if nums else (0,)


def audit_local_dependencies(root_dir: Path | str, target_label: str | None = None) -> list[Finding]:
    """Audit local dependency manifests (requirements.txt, package.json, composer.json, go.mod)."""
    root = Path(root_dir).resolve()
    if not root.exists():
        return []
    label = target_label or f"deps://{root.name}"
    findings: list[Finding] = []

    manifests: list[Path] = [root] if root.is_file() else []
    if root.is_dir():
        for name in ("requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "composer.json", "go.mod"):
            cand = root / name
            if cand.is_file():
                manifests.append(cand)

    for mf in manifests:
        try:
            text = mf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = mf.name
        parsed_deps: list[tuple[str, str]] = []

        if mf.name == "requirements.txt":
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([=<>!~]+)?\s*([0-9][0-9A-Za-z.*\-]*)?", line)
                if m:
                    pkg, op, ver = m.group(1), m.group(2) or "", m.group(3) or ""
                    parsed_deps.append((pkg, f"{op}{ver}".strip()))
        elif mf.name in ("package.json", "composer.json"):
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            if isinstance(data, dict):
                for section in ("dependencies", "devDependencies", "require", "require-dev"):
                    sec = data.get(section)
                    if isinstance(sec, dict):
                        for k, v in sec.items():
                            parsed_deps.append((str(k), str(v)))
        elif mf.name == "package-lock.json":
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            pkgs = data.get("dependencies", {}) if isinstance(data, dict) else {}
            if isinstance(pkgs, dict):
                for k, v in list(pkgs.items())[:200]:
                    if isinstance(v, dict) and "version" in v:
                        parsed_deps.append((str(k), f"=={v['version']}"))
        elif mf.name == "go.mod":
            for m in re.finditer(r"(?m)^\s*([a-zA-Z0-9_.\-/]+)\s+v([0-9]+\.[0-9]+\.[0-9]+)", text):
                parsed_deps.append((m.group(1), f"=={m.group(2)}"))

        unpinned: list[str] = []
        for pkg, spec in parsed_deps:
            key = pkg.lower().strip()
            if not spec or spec in ("*", "latest") or (spec.startswith(">=") and "," not in spec):
                unpinned.append(f"{pkg}{spec}")
            ver_digits = re.findall(r"\d+\.\d+(?:\.\d+)?", spec)
            if not ver_digits:
                continue
            ver_str = ver_digits[0]
            if key in LOCAL_PACKAGE_ADVISORIES:
                eco, floor, cve_id, sev, summary = LOCAL_PACKAGE_ADVISORIES[key]
                if _parse(ver_str) < floor:
                    floor_str = ".".join(map(str, floor))
                    is_pinned = spec.startswith(("==", "=")) or ( re.match(r"^\d", spec) is not None )
                    findings.append(Finding(
                        target=label,
                        url=f"{rel}:{pkg}",
                        endpoint=rel,
                        category="Dependency Security",
                        module="dependency_audit",
                        title=f"Vulnerable {eco} dependency: {pkg} {ver_str} ({cve_id})",
                        severity=sev,
                        cwe="CWE-1395",
                        cve=cve_id,
                        description=f"{summary}. Declared in {rel} as '{pkg} {spec}' (below safe floor {floor_str}).",
                        evidence=f"{rel} -> {pkg} {spec}",
                        detection_method="Manifest & advisory correlation",
                        confidence=CONFIRMED if is_pinned else POTENTIAL,
                        remediation=f"Upgrade {pkg} to >= {floor_str} and regenerate lockfiles.",
                        tags=["dependency", eco.lower(), cve_id.lower()],
                    ))

        if unpinned:
            findings.append(Finding(
                target=label,
                url=rel,
                endpoint=rel,
                category="Dependency Security",
                module="dependency_audit",
                title=f"Unpinned dependency ranges in {rel}",
                severity=LOW,
                cwe="CWE-1395",
                description=(
                    f"{len(unpinned)} dependency specification(s) in {rel} do not pin an exact version or upper bound, "
                    "increasing supply-chain drift and tampering risk."
                ),
                evidence=f"{rel}: {', '.join(unpinned[:10])}",
                detection_method="Manifest pin inspection",
                confidence=CONFIRMED,
                remediation="Pin exact dependency versions and commit cryptographic lockfiles (requirements.lock, package-lock.json).",
                tags=["dependency", "supply-chain"],
            ))
    return findings


class DependencyAuditModule(BaseModule):
    name = "dependency_audit"
    category = "Framework Auditing"

    async def run(self, ctx):
        out = []
        resp = getattr(ctx, "homepage", None)
        if resp is not None:
            out += self._frontend(ctx, resp)
            out += await self._manifests(ctx)
        src_path = ctx.config.get("source.path")
        if src_path:
            out += audit_local_dependencies(src_path, target_label=ctx.target.url)
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
                ctx,
                title=f"{product} {version} referenced ({label})",
                severity=sev,
                cwe="CWE-1395",
                description=f"{product} {version} detected in page markup ({note}). Confirm the "
                            "vulnerable code path is reachable.",
                evidence=f"matched: {m.group(0)[:120]}",
                detection_method="Source regex",
                confidence=HIGH_CONF if sev != INFO else CONFIRMED,
                remediation=f"Upgrade {product} to at least {'.'.join(map(str, floor))} or latest.",
                tags=["dependency", product.lower()],
            ))
        return out

    async def _manifests(self, ctx):
        out = []
        for path, label in (
            ("/package.json", "Node"),
            ("/composer.json", "PHP"),
            ("/composer.lock", "PHP lock"),
            ("/package-lock.json", "Node lock"),
        ):
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
                ctx,
                title=f"{label} dependency manifest exposed ({path})",
                severity=MEDIUM,
                cwe="CWE-200",
                description=f"{len(deps)} declared dependencies are readable, giving an exact "
                            "supply-chain map for CVE matching.",
                evidence=f"GET {url} -> 200\n" + ", ".join(sorted(deps)[:25]),
                detection_method="Manifest probe",
                confidence=CONFIRMED,
                remediation=f"Block or relocate {path} outside the document root.",
                tags=["dependency", "disclosure"],
            ))
        return out
