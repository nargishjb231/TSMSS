"""Per-target module orchestration with timeouts, scoring and isolation."""
from __future__ import annotations

import asyncio
import time
import traceback

from config import SEVERITY_WEIGHTS
from core.context import ScanContext, Target
from core.finding import Finding, severity_rank
from core.logger import get

log = get("tsmss.engine")

MODULE_ORDER = [
    "dns_security", "ssl_tls", "http_security", "cookies", "cors",
    "information_disclosure", "framework_audit", "api_security",
    "authentication", "authorization", "dependency_audit",
    "vulnerability_indicators", "infrastructure",
]


def build_modules(rules: dict) -> list:
    from modules import (api_security, authentication, authorization, cookies, cors,
                         dependency_audit, dns_security, framework_audit, http_security,
                         information_disclosure, infrastructure, ssl_tls,
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
    }
    return [registry[name]() for name in MODULE_ORDER if name in registry]


def score(findings: list[Finding]) -> tuple[int, str]:
    deduction = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    value = max(0, min(100, 100 - deduction))
    if value >= 90:
        return value, "A"
    if value >= 80:
        return value, "B"
    if value >= 65:
        return value, "C"
    if value >= 50:
        return value, "D"
    if value >= 30:
        return value, "E"
    return value, "F"


class TargetEngine:
    def __init__(self, config, rules: dict, scope, make_http):
        self.config = config
        self.rules = rules
        self.scope = scope
        self.make_http = make_http
        self.modules = build_modules(rules)

    async def scan(self, url: str, stop_event: asyncio.Event) -> tuple[list[Finding], int, str, int]:
        started = time.monotonic()
        counter: dict = {"requests": 0}
        target = Target(url)
        findings: list[Finding] = []
        error = ""
        module_timeout = float(self.config.get("scan.module_timeout", 120))
        target_timeout = float(self.config.get("scan.target_timeout", 900))

        async with self.make_http(stop_event, counter) as http:
            ctx = ScanContext(target=target, config=self.config, scope=self.scope,
                              http=http, stop_event=stop_event, counter=counter)
            try:
                await asyncio.wait_for(self._run_modules(ctx, findings, module_timeout),
                                       timeout=target_timeout)
            except asyncio.TimeoutError:
                error = f"target timeout after {target_timeout:.0f}s"
            except Exception as exc:  # noqa: BLE001
                error = f"{type(exc).__name__}: {exc}"
                log.warning("target %s failed: %s\n%s", url, error, traceback.format_exc(limit=3))

        findings.sort(key=lambda f: (severity_rank(f.severity), f.title))
        value, grade = score(findings)
        ctx_grade = grade
        elapsed = int(time.monotonic() - started)
        return findings, value, error or ctx_grade, counter["requests"]

    async def _run_modules(self, ctx, sink: list, timeout: float) -> None:
        for module in self.modules:
            if ctx.stop_event.is_set():
                return
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