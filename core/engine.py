"""Per-target module orchestration with timeouts, scoring and isolation."""
from __future__ import annotations

import asyncio
import time
import traceback
from collections import Counter
from dataclasses import dataclass, field

from config import SEVERITY_WEIGHTS
from core.context import ScanContext, Target
from core.finding import Finding, score_counts, severity_rank
from core.logger import get

log = get("tsmss.engine")


@dataclass
class TargetScanResult:
    url: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    requests: int = 0
    ok: bool = True
    error: str = ""
    elapsed_s: int = 0

MODULE_ORDER = [
    "dns_security", "ssl_tls", "http_security", "cookies", "cors",
    "information_disclosure", "framework_audit", "api_security",
    "authentication", "authorization", "dependency_audit",
    "vulnerability_indicators", "infrastructure", "external_tools",
]


_CONF_ORDER = {"CONFIRMED": 0, "HIGH CONFIDENCE": 1, "MEDIUM CONFIDENCE": 2,
               "LOW CONFIDENCE": 3, "NEEDS MANUAL VERIFICATION": 4, "HEURISTIC": 4, "MANUAL": 4}


def _dedupe(findings: list, min_conf: str = "") -> list:
    """Drop repeats of the same (title, parameter) and anything below min_conf."""
    floor = _CONF_ORDER.get((min_conf or "").upper())
    seen, out = set(), []
    for f in findings:
        if floor is not None and _CONF_ORDER.get(f.confidence, 9) > floor:
            continue
        key = (f.title, f.parameter, f.severity)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def build_modules(rules: dict, disabled=None) -> list:
    from modules import (api_security, authentication, authorization, cookies, cors,
                         dependency_audit, dns_security, framework_audit, http_security,
                         external_tools, information_disclosure, infrastructure, ssl_tls,
                         vulnerability_indicators)
    registry = {
        "dns_security": dns_security.DnsSecurityModule,
        "ssl_tls": ssl_tls.SslTlsModule,
        "http_security": lambda: http_security.HttpSecurityModule(rules),
        "cookies": cookies.CookieModule,
        "cors": cors.CorsModule,
        "information_disclosure": information_disclosure.InformationDisclosureModule,
        "framework_audit": framework_audit.FrameworkAuditModule,
        "api_security": api_security.ApiSecurityModule,
        "authentication": authentication.AuthenticationModule,
        "authorization": authorization.AuthorizationModule,
        "dependency_audit": dependency_audit.DependencyAuditModule,
        "vulnerability_indicators": vulnerability_indicators.VulnerabilityIndicatorModule,
        "infrastructure": infrastructure.InfrastructureModule,
        "external_tools": external_tools.ExternalToolsModule,
    }
    skip_modules = set(disabled or [])
    return [registry[name]() for name in MODULE_ORDER
            if name in registry and name not in skip_modules]


def score(findings: list[Finding]) -> tuple[int, str]:
    """Thin wrapper over finding.score_counts, kept for existing callers."""
    return score_counts(Counter(f.severity for f in findings))


class TargetEngine:
    def __init__(self, config, rules: dict, scope, make_http, evidence=None):
        self.config = config
        self.rules = rules
        self.scope = scope
        self.make_http = make_http
        self.evidence = evidence
        self.disabled_modules = list(config.get("modules.disabled", []) or [])
        self.modules = build_modules(rules, self.disabled_modules)

    async def scan(self, url: str, stop_event: asyncio.Event) -> TargetScanResult:
        started = time.monotonic()
        counter: dict = {"requests": 0}
        target = Target(url)
        findings: list[Finding] = []
        error = ""
        module_timeout = float(self.config.get("scan.module_timeout", 120))
        target_timeout = float(self.config.get("scan.target_timeout", 900))

        async with self.make_http(stop_event, counter) as http:
            ctx = ScanContext(target=target, config=self.config, scope=self.scope,
                              http=http, stop_event=stop_event, counter=counter,
                              evidence=self.evidence)
            try:
                await asyncio.wait_for(self._run_modules(ctx, findings, module_timeout),
                                       timeout=target_timeout)
            except asyncio.TimeoutError:
                error = f"target timeout after {target_timeout:.0f}s"
            except Exception as exc:  # noqa: BLE001
                error = f"{type(exc).__name__}: {exc}"
                log.warning("target %s failed: %s\n%s", url, error, traceback.format_exc(limit=3))

        findings = _dedupe(findings, self.config.get("scan.min_confidence", ""))
        findings.sort(key=lambda f: (severity_rank(f.severity), f.title))
        value, grade = score(findings)
        if not error and not findings and getattr(ctx, "http_unreachable", ""):
            error = getattr(ctx, "http_unreachable")
        elapsed = int(time.monotonic() - started)
        return TargetScanResult(
            url=url,
            findings=findings,
            score=value,
            grade=grade,
            requests=counter["requests"],
            ok=not bool(error),
            error=error,
            elapsed_s=elapsed,
        )

    async def _run_modules(self, ctx, sink: list, timeout: float) -> None:
        for module in self.modules:
            if ctx.stop_event.is_set():
                return
            if getattr(ctx, "http_unreachable", "") and getattr(module, "needs_http", True):
                continue
            try:
                result = await asyncio.wait_for(module.run(ctx), timeout=timeout)
            except asyncio.TimeoutError:
                log.info("module %s timed out on %s", module.name, ctx.target.url)
                continue
            except Exception as exc:  # noqa: BLE001
                log.info("module %s errored on %s: %s", module.name, ctx.target.url, exc)
                continue
            for finding in result or []:
                if not finding.url:
                    finding.url = ctx.target.url
                sink.append(finding)