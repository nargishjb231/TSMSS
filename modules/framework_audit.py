"""Framework fingerprinting plus framework-specific exposure checks."""
from __future__ import annotations

import re

from core.finding import CONFIRMED, HIGH_CONF, CRITICAL, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule

SIGNATURES = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r'name="generator" content="WordPress'],
    "Laravel": [r"laravel_session", r"X-XSRF-TOKEN"],  # wordpress-fingerprint
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Rails": [r"csrf-token.*authenticity_token", r"_rails_session", r"X-Runtime"],
    "Next.js": [r"__NEXT_DATA__", r"/_next/static/"],
    "Nuxt": [r"__NUXT__", r"/_nuxt/"],
    "Spring Boot": [r"Whitelabel Error Page", r"X-Application-Context"],
    "Express": [r"X-Powered-By: Express"],
    "Drupal": [r"Drupal.settings", r"/sites/default/files/", r"X-Generator: Drupal"],
    "Joomla": [r"/media/system/js/", r'content="Joomla'],
    "ASP.NET": [r"__VIEWSTATE", r"X-AspNet-Version"],
    "Flask": [r"Werkzeug/"],
}

FRAMEWORK_PATHS = {
    "WordPress": {
        "/wp-json/wp/v2/users": ("WordPress REST user enumeration", MEDIUM, "CWE-200",
                                 r'"slug"|"name"'),
        "/?author=1": ("WordPress author archive enumeration", LOW, "CWE-200", r"author"),
        "/wp-config.php.bak": ("WordPress config backup", CRITICAL, "CWE-530", r"DB_PASSWORD"),
        "/xmlrpc.php": ("WordPress XML-RPC enabled", LOW, "CWE-16", r"XML-RPC server accepts POST"),
    },
    "Laravel": {
        "/.env": ("Laravel dotenv exposure", CRITICAL, "CWE-538", r"APP_KEY|DB_"),
        "/storage/logs/laravel.log": ("Laravel log file exposure", HIGH, "CWE-532", r"local\.ERROR|production\.ERROR"),
        "/_ignition/health-check": ("Laravel Ignition endpoint", LOW, "CWE-200", r"can_execute_commands"),
        "/telescope": ("Laravel Telescope debug console", HIGH, "CWE-200", r"Telescope|requests"),
    },
    "Django": {
        "/admin/": ("Django admin interface", INFO, "CWE-200", r"Site administration|Django administration"),
        "/static/admin/css/base.css": ("Django static admin assets", INFO, "CWE-200", r"body"),
    },
    "Spring Boot": {
        "/actuator": ("Spring Actuator index", MEDIUM, "CWE-200", r'"_links"|actuator'),
        "/actuator/env": ("Spring Actuator environment dump", HIGH, "CWE-200", r"propertySources|systemProperties"),
        "/actuator/health": ("Spring Actuator health", INFO, "CWE-200", r'"status"'),
        "/actuator/mappings": ("Spring Actuator route map", MEDIUM, "CWE-200", r"dispatcherServlets"),
    },
    "Drupal": {
        "/CHANGELOG.txt": ("Drupal changelog (version disclosure)", LOW, "CWE-200", r"Drupal \d"),
        "/core/CHANGELOG.txt": ("Drupal core changelog", LOW, "CWE-200", r"Drupal \d"),
    },
}


class FrameworkAuditModule(BaseModule):
    name = "framework_audit"
    category = "Framework Auditing"

    async def run(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        blob = resp.body[:200_000] + " " + " ".join(f"{k}: {v}" for k, v in resp.headers.items())
        detected = [name for name, pats in SIGNATURES.items()
                    if any(re.search(p, blob, re.I) for p in pats)]
        out = []
        if detected:
            ctx.frameworks = detected
            out.append(self.make(
                ctx, title=f"Application framework fingerprint: {', '.join(detected)}",
                severity=INFO,
                description="Framework signatures were matched in markup or headers. Fingerprints "
                            "are inferential, not proof.",
                evidence="\n".join(
                    f"{name}: matched" for name in detected),
                detection_method="Signature matching", confidence=HIGH_CONF,
                remediation="Reduce version leakage where practical.",
                tags=["framework", "fingerprint"]))
        for name in detected:
            for path, (title, sev, cwe, pattern) in FRAMEWORK_PATHS.get(name, {}).items():
                url = str(ctx.target.root).rstrip("/") + path
                r = await ctx.http.request("GET", url, retry=False)
                if not r.ok or r.status != 200:
                    continue
                if pattern and not re.search(pattern, r.body[:20000], re.I):
                    continue
                out.append(self.make(
                    ctx, title=title, severity=sev, cwe=cwe,
                    description=f"{name}-specific endpoint is publicly reachable.",
                    evidence=f"GET {url} -> 200\n{r.body[:500]}",
                    detection_method=f"{name} path probe", confidence=CONFIRMED,
                    remediation=f"Restrict or authenticate {path} for {name}.",
                    tags=["framework", name.lower()]))
        return out