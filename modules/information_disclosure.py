"""Debug, listing, backup and config exposure indicators."""
from __future__ import annotations

import re

from core.finding import CONFIRMED, HIGH_CONF, CRITICAL, HIGH, INFO, LOW, MEDIUM, NEEDS_MANUAL
from modules.base import BaseModule

PATHS = {
    "/.git/HEAD": ("Git repository metadata", HIGH, "CWE-538",
                   r"ref:\s+refs/heads/|^[0-9a-f]{40}$"),
    "/.git/config": ("Git configuration", HIGH, "CWE-538", r"\[core\]|repositoryformatversion"),
    "/.env": ("Dotenv configuration file", CRITICAL, "CWE-538",
              r"^[A-Z0-9_]+\s*="),
    "/.env.local": ("Dotenv configuration file", HIGH, "CWE-538", r"^[A-Z0-9_]+\s*="),
    "/config.php.bak": ("PHP config backup", HIGH, "CWE-530", r"<\?php|DB_"),
    "/wp-config.php.bak": ("WordPress config backup", CRITICAL, "CWE-530", r"DB_PASSWORD|wp-config"),
    "/backup.zip": ("Backup archive", HIGH, "CWE-530", r"PK\x03\x04|"),
    "/backup.sql": ("Database dump", HIGH, "CWE-530", r"CREATE TABLE|INSERT INTO"),
    "/phpinfo.php": ("phpinfo() output", MEDIUM, "CWE-200", r"PHP Version|phpinfo\(\)"),
    "/server-status": ("Apache server-status", LOW, "CWE-200", r"Apache Server Status|requests currently being processed"),
    "/.htaccess": ("Apache access control file", LOW, "CWE-538", r"RewriteEngine|AddType|Options"),
    "/composer.json": ("Composer manifest", LOW, "CWE-538", r'"require"\s*:|"name"\s*:'),
    "/package.json": ("Node manifest", LOW, "CWE-538", r'"dependencies"\s*:|"name"\s*:'),
    "/Dockerfile": ("Docker build file", LOW, "CWE-538", r"^FROM\s+", ),
    "/.DS_Store": ("macOS metadata file", INFO, "CWE-538", r"Bud1"),
}

DIR_LIST_RE = re.compile(r"(?i)<title>\s*Index of /|<h1>\s*Index of /")


class InformationDisclosureModule(BaseModule):
    name = "information_disclosure"
    category = "Application Security"

    async def run(self, ctx):
        out = []
        base = str(ctx.target.root).rstrip("/")
        for path, (label, sev, cwe, pattern) in PATHS.items():
            url = base + path
            resp = await ctx.http.request("GET", url, retry=False)
            if not resp.ok or resp.status != 200 or len(resp.body) < 6:
                continue
            if pattern and not re.search(pattern, resp.body[:6000], re.M):
                continue
            out.append(self.make(
                ctx, title=f"Exposed {label} ({path})",
                severity=sev, cwe=cwe,
                description=f"{path} is publicly readable and matches the expected signature "
                            "for this artefact.",
                evidence=f"GET {url} -> 200\n{resp.body[:600]}",
                detection_method="Direct path probe", confidence=CONFIRMED,
                remediation=f"Serve or block {path} explicitly at the web server.",
                tags=["disclosure", "exposure"]))
        out += await self._listing(ctx, base)
        out += await self._debug_params(ctx)
        return out

    async def _listing(self, ctx, base):
        out = []
        for path in ("/", "/uploads/", "/assets/", "/static/", "/images/", "/files/"):
            url = base + path
            resp = await ctx.http.request("GET", url, retry=False)
            if resp.ok and resp.status == 200 and DIR_LIST_RE.search(resp.body[:4000]):
                out.append(self.make(
                    ctx, title=f"Directory listing enabled at {path}",
                    severity=MEDIUM, cwe="CWE-548",
                    description="The server returns an index page enumerating directory contents.",
                    evidence=f"GET {url} -> 200\n{resp.body[:500]}",
                    detection_method="Directory index signature", confidence=CONFIRMED,
                    remediation="Disable autoindex or add index files.",
                    tags=["disclosure", "listing"]))
        return out

    async def _debug_params(self, ctx):
        out = []
        sep = "&" if "?" in ctx.target.url else "?"
        for param, value in (("debug=1", None), ("test=1", None), ("_profiler=1", None)):
            probe = ctx.target.url + sep + param
            resp = await ctx.http.request("GET", probe, retry=False)
            if not resp.ok:
                continue
            markers = [m for m in ("Symfony Profiler", "Django", "DEBUG =", "SQL Profiler",
                                   "xdebug", "Query Monitor", "whoops") if m.lower() in resp.body.lower()]
            if markers:
                out.append(self.make(
                    ctx, title=f"Debug mode reactivated by query parameter {param}",
                    severity=LOW, cwe="CWE-489",
                    description=f"Debug markers appeared: {', '.join(markers)}.",
                    evidence=f"GET {probe} -> {resp.status}\n{resp.body[:400]}",
                    detection_method="Debug parameter probe", confidence=HIGH_CONF,
                    remediation="Pin debug mode off in production configuration.",
                    tags=["disclosure", "debug"]))
                break
        return out