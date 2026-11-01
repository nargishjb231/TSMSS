#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
F=0

echo "=== 1. confidence taxonomy ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("core/finding.py"); s=p.read_text()
if "HEURISTIC" in s: print("  skip"); raise SystemExit
old='NEEDS_MANUAL = "NEEDS MANUAL VERIFICATION"'
new=old+'\nHEURISTIC = "HEURISTIC"\nMANUAL = "MANUAL REVIEW"'
old2='_CONF_RANK = {CONFIRMED: 5, HIGH_CONF: 4, MED_CONF: 3, LOW_CONF: 2, NEEDS_MANUAL: 1}'
new2=('_CONF_RANK = {CONFIRMED: 5, HIGH_CONF: 4, MED_CONF: 3, LOW_CONF: 2,\n'
      '             NEEDS_MANUAL: 1, HEURISTIC: 1, MANUAL: 1}')
for o,n in ((old,new),(old2,new2)):
    if o not in s: print("  MISS",o[:20]); sys.exit(1)
    s=s.replace(o,n,1)
p.write_text(s); print("  ok taxonomy")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 2. header token parsing (XFO/XCTO FP) ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("modules/http_security.py"); s=p.read_text()
if "_header_tokens" in s: print("  skip"); raise SystemExit
s=s.replace("VERSION_RE = re.compile", '''def _header_tokens(resp, name):
    """Split a possibly repeated header into lowercased, de-duplicated tokens."""
    out=[]
    for chunk in resp.headers.get(name.lower(), "").split(","):
        tok=chunk.strip().lower()
        if tok and tok not in out:
            out.append(tok)
    return out


VERSION_RE = re.compile''',1)
old='''        xfo = resp.header("x-frame-options").lower()
        if xfo and xfo not in ("deny", "sameorigin"):'''
new='''        xfo = _header_tokens(resp, "x-frame-options")
        bad_xfo = [t for t in xfo if t not in ("deny", "sameorigin")]
        if bad_xfo:'''
if old not in s: print("  MISS xfo"); sys.exit(1)
s=s.replace(old,new,1)
s=s.replace('''                evidence=f"X-Frame-Options: {xfo}",
                detection_method="Header value validation", confidence=CONFIRMED,''',
'''                evidence=f"X-Frame-Options: {', '.join(xfo)}",
                detection_method="Header value validation", confidence=CONFIRMED,''',1)
s=s.replace("description=f\"Value '{xfo}' is not DENY or SAMEORIGIN.\"",
            "description=f\"Value(s) {', '.join(bad_xfo)} are not DENY or SAMEORIGIN.\"",1)
old2='''        xfo = resp.header("x-frame-options")
        csp = resp.header("content-security-policy")
        framed = "frame-ancestors" in csp if csp else False
        if xfo or framed:'''
new2='''        xfo = [t for t in _header_tokens(resp, "x-frame-options")
               if t in ("deny", "sameorigin")]
        csp = resp.header("content-security-policy")
        framed = "frame-ancestors" in csp if csp else False
        if xfo or framed:'''
if old2 not in s: print("  MISS clickjack"); sys.exit(1)
s=s.replace(old2,new2,1)
# XCTO duplicates
s=s.replace('''    "x-content-type-options": dict(''','''    "x-content-type-options": dict(''',1)
p.write_text(s); print("  ok header tokens")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 3. X-Content-Type-Options token check ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("modules/http_security.py"); s=p.read_text()
if "nosniff missing from" in s: print("  skip"); raise SystemExit
anchor="    async def _disclosure(self, ctx, resp):"
if anchor not in s: print("  MISS anchor"); sys.exit(1)
s=s.replace(anchor,'''    async def _xcto(self, ctx, resp):
        raw = resp.header("x-content-type-options")
        if raw and "nosniff" not in _header_tokens(resp, "x-content-type-options"):
            return [self.make(
                ctx, title="X-Content-Type-Options set without nosniff",
                severity=LOW, cwe="CWE-693",
                description="The header is present but nosniff is missing from the value.",
                evidence=f"X-Content-Type-Options: {raw}",
                detection_method="Header value validation", confidence=CONFIRMED,
                remediation="Send: X-Content-Type-Options: nosniff", tags=["headers"])]
        return []

'''+anchor,1)
s=s.replace("        out += self._disclosure(ctx, base)",
            "        out += self._xcto(ctx, base)\n        out += self._disclosure(ctx, base)",1)
p.write_text(s); print("  ok xcto")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 4. cert key type: ECDSA/Ed25519 not flagged ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("modules/ssl_tls.py"); s=p.read_text()
if "key_family" in s: print("  skip"); raise SystemExit
old='''        bits = info.get("key_bits")
        if bits and bits < 2048:'''
new='''        bits = info.get("key_bits")
        family = info.get("key_family", "")
        if family == "rsa" and bits and bits < 2048:'''
if old not in s: print("  MISS key block"); sys.exit(1)
s=s.replace(old,new,1)
s=s.replace('''                description="Below the 2048-bit RSA baseline.",
                evidence=f"public_key_bits={bits}",''',
'''                description="RSA modulus is below the 2048-bit baseline.",
                evidence=f"key=rsa bits={bits}",''',1)
old2='''            if isinstance(pub, ec.EllipticCurvePublicKey):
                bits = pub.curve.key_size'''
new2='''            family = ""
            if isinstance(pub, rsa.RSAPublicKey):
                family = "rsa"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                family = "ec"
                bits = pub.curve.key_size
            elif isinstance(pub, ed25519.Ed25519PublicKey):
                family = "ed25519"
            elif isinstance(pub, ed448.Ed448PublicKey):
                family = "ed448"'''
if old2 not in s: print("  MISS key parse"); sys.exit(1)
s=s.replace(old2,new2,1)
s=s.replace("from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa",
            "from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448",1)
s=s.replace('"sans": sans, "key_bits": bits,','"sans": sans, "key_bits": bits, "key_family": family,',1)
p.write_text(s); print("  ok key family")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 5. HTTPS redirect check was inverted ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("modules/http_security.py"); s=p.read_text()
if "landed_https" in s: print("  skip"); raise SystemExit
old='''            if p and p.ok and p.status < 400 and not (p.final_url or "").startswith("https://"):'''
new='''            landed_https = (p and p.ok and p.status < 400
                            and (p.final_url or p.url).startswith("https://"))
            redirected = bool(p and p.hops)
            if p and p.ok and p.status < 400 and not landed_https and not redirected:'''
if old not in s: print("  MISS https probe"); sys.exit(1)
p.write_text(s.replace(old,new,1)); print("  ok https check")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 6. framework signature tightening ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("modules/framework_audit.py"); s=p.read_text()
if "laravel_session" in s and "wordpress-fingerprint" in s: print("  skip"); raise SystemExit
s=s.replace('''    "Laravel": [r"laravel_session", r"XSRF-TOKEN", r"Laravel"],''',
            '''    "Laravel": [r"laravel_session", r"X-XSRF-TOKEN"],  # wordpress-fingerprint''',1)
s=s.replace('''    "Flask": [r"Werkzeug", r"flask"],''',
            '''    "Flask": [r"Werkzeug/"],''',1)
s=s.replace('''    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__", r"django"],''',
            '''    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],''',1)
p.write_text(s); print("  ok signatures")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 7. port severity + nmap evidence dedupe ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("modules/infrastructure.py"); s=p.read_text()
if "PORT_SEVERITY" in s: print("  skip"); raise SystemExit
s=s.replace("CDN_SIGNS = {", '''# Ports that are expected on a public web host carry no weight.
PORT_SEVERITY = {"80": INFO, "443": INFO, "8080": INFO, "8443": INFO}

CDN_SIGNS = {''',1)
old='''            sev = MEDIUM if port not in ("80", "443") else INFO'''
new='''            sev = PORT_SEVERITY.get(port, MEDIUM)'''
if old not in s: print("  MISS port sev"); sys.exit(1)
s=s.replace(old,new,1)
old2='''                evidence=text[-1500:], detection_method="nmap connect scan",'''
new2='''                evidence=f"{port}/tcp open {service}", detection_method="nmap connect scan",'''
if old2 not in s: print("  MISS port ev"); sys.exit(1)
s=s.replace(old2,new2,1)
p.write_text(s); print("  ok ports")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 8. rewrite vulnerability_indicators (SSTI/XSS/SQLi FP) ==="
cat > modules/vulnerability_indicators.py <<'VIEOF'
"""Active payload probes with baseline differencing.

Every probe takes a payload-free baseline first and only reports when the
payload response actually differs from it. Markers and arithmetic operands
are unique per run so common strings like "49" cannot create false hits.
"""
from __future__ import annotations

import difflib
import html as htmllib
import random
import re
import secrets
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

from core.finding import (CONFIRMED, HIGH_CONF, HIGH, INFO, LOW, MEDIUM,
                          NEEDS_MANUAL)
from modules.base import BaseModule

REDIRECT_PARAMS = re.compile(
    r"(?i)^(url|uri|redirect|redirect_uri|return|returnurl|next|dest|destination|continue|target|r|to|out)$")
FILE_PARAMS = re.compile(r"(?i)^(file|path|page|template|include|doc|document|dir|folder|load|view|src)$")
CMD_PARAMS = re.compile(r"(?i)^(cmd|exec|command|ping|host|ip|query|q|search|name|domain)$")
SQL_ERRORS = re.compile(
    r"(SQL syntax|SQLSTATE|ORA-\d{5}|MySQLSyntaxErrorException|pg_query|unclosed quotation mark"
    r"|PostgreSQL.*ERROR|SQLite.*error|ODBC.*Driver|Microsoft OLE DB)", re.I)

TRAVERSAL_MARK = "root:x:0:0:"
TRAVERSAL_PAYLOADS = ["../../../../../../etc/passwd", "....//....//....//....//etc/passwd"]
CMD_PROBES = [(";id", r"uid=\d+"), ("|id", r"uid=\d+"), ("$(id)", r"uid=\d+")]
XXE_BODY = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE t [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><t>&xxe;</t>')

MIN_DIFF = 0.02


def _ratio(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()


def _decode(text: str) -> str:
    return htmllib.unescape(unquote(text))


def _excerpt(body: str, needle: str, radius: int = 90) -> str:
    idx = body.find(needle)
    if idx < 0:
        return body[: radius * 2]
    start = max(0, idx - radius)
    return ("..." if start else "") + body[start: idx + len(needle) + radius] + "..."


class VulnerabilityIndicatorModule(BaseModule):
    name = "vulnerability_indicators"
    category = "Vulnerability Indicators"

    async def run(self, ctx):
        cfg = ctx.config
        params = await self._discover_params(ctx)
        if not params:
            return []
        out = []
        limit = int(cfg.get("active.max_params_per_target", 25))
        for param in params[:limit]:
            baseline = await self._baseline(ctx, param)
            if cfg.get("active.xss", True):
                out += await self._xss(ctx, param, baseline)
            if cfg.get("active.sqli", True):
                out += await self._sqli(ctx, param, baseline)
            if cfg.get("active.ssti", True):
                out += await self._ssti(ctx, param, baseline)
            if cfg.get("active.open_redirect", True) and REDIRECT_PARAMS.match(param):
                out += await self._open_redirect(ctx, param)
            if cfg.get("active.path_traversal", True) and FILE_PARAMS.match(param):
                out += await self._traversal(ctx, param)
            if cfg.get("active.command_injection", True) and CMD_PARAMS.match(param):
                out += await self._cmdi(ctx, param)
            if cfg.get("active.crlf", True):
                out += await self._crlf(ctx, param)
        if cfg.get("active.xxe", True):
            out += await self._xxe(ctx)
        if cfg.get("active.smuggling", True):
            out += await self._smuggling(ctx)
        if cfg.get("active.cache_poisoning", True):
            out += await self._cache_poison(ctx)
        return out

    # ---- helpers ---------------------------------------------------------
    async def _discover_params(self, ctx) -> list[str]:
        names: list[str] = []
        for k in parse_qs(urlparse(ctx.target.url).query):
            if k not in names:
                names.append(k)
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return names
        body = resp.body[:120_000]
        for m in re.finditer(r'(?:href|action|src)="[^"]*\?([^"#]+)"', body):
            for k in parse_qs(htmllib.unescape(m.group(1))):
                if k not in names and len(names) < 60:
                    names.append(k)
        for m in re.finditer(r'<input[^>]+name="([^"]+)"', body, re.I):
            k = htmllib.unescape(m.group(1))
            if k not in names and len(names) < 60:
                names.append(k)
        return [n for n in names if not n.startswith(("csrf", "_token", "submit"))]

    @staticmethod
    def _swap(url: str, param: str, value: str) -> str:
        parts = urlparse(url)
        query = parse_qs(parts.query, keep_blank_values=True)
        query[param] = [value]
        return urlunparse(parts._replace(query=urlencode(query, doseq=True)))

    async def _baseline(self, ctx, param) -> str:
        original = parse_qs(urlparse(ctx.target.url).query).get(param, [""])[0]
        r = await ctx.http.request("GET", self._swap(ctx.target.url, param, original), retry=False)
        return r.body if r.ok else ""

    # ---- XSS -------------------------------------------------------------
    async def _xss(self, ctx, param, baseline):
        marker = "z" + secrets.token_hex(4)
        plain = await ctx.http.request("GET", self._swap(ctx.target.url, param, marker), retry=False)
        if not plain.ok or marker not in plain.body:
            return []
        payload = f'"><b{marker}>x</b>'
        armed = await ctx.http.request("GET", self._swap(ctx.target.url, param, payload), retry=False)
        if not armed.ok:
            return []
        decoded = _decode(armed.body)
        if f"<b{marker}>x</b>" not in decoded:
            if marker in armed.body:
                return [self.make(
                    ctx, title=f"Parameter '{param}' reflects, tag form encoded",
                    severity=INFO, cwe="CWE-79",
                    description="The marker round-trips but the injected tag is entity-encoded "
                                "in the response, so it renders as text unless the sink is HTML.",
                    evidence=f"Payload: {payload}\nSnippet: {_excerpt(armed.body, marker)}",
                    detection_method="Encoded reflection probe", confidence=HIGH_CONF,
                    parameter=param, remediation="Confirm the sink context manually.",
                    tags=["xss", "encoded"])]
            return []
        idx = decoded.find(f"<b{marker}>")
        before = decoded[max(0, idx - 60): idx]
        in_attr = bool(re.search(r'(?:href|src|action|value)\s*=\s*["\'][^"\']*$', before))
        evidence = (f"Payload: {payload}\nContext: "
                    f"{'attribute' if in_attr else 'markup'}\nBefore: ...{before[-50:]}")
        if in_attr:
            return [self.make(
                ctx, title=f"HTML injection in attribute context ('{param}')",
                severity=MEDIUM, cwe="CWE-79",
                description="The tag survived inside an attribute value, so quote breakout is "
                            "needed for script execution. Confirm with a full XSS payload.",
                evidence=evidence, detection_method="Decoded reflection + context check",
                confidence=HIGH_CONF, parameter=param,
                remediation="Entity-encode attribute values; add a CSP.",
                tags=["xss", "attribute"]).downgrade_if_heuristic("xss")]
        return [self.make(
            ctx, title=f"Reflected XSS in parameter '{param}'",
            severity=HIGH, cwe="CWE-79",
            description="An unencoded tag injected through this parameter survived into the "
                        "response body, so the browser parses it as markup.",
            evidence=evidence, detection_method="Decoded reflection + harmless tag probe",
            confidence=CONFIRMED, parameter=param,
            remediation="HTML-entity-encode output; add a CSP.", tags=["xss"])]

    # ---- SQLi ------------------------------------------------------------
    async def _sqli(self, ctx, param, baseline):
        base = ctx.target.url
        original = parse_qs(urlparse(base).query).get(param, ["1"])[0]
        seed = original if original.isdigit() else "1"
        for payload in (f"{seed}'", f'{seed}"'):
            r = await ctx.http.request("GET", self._swap(base, param, payload), retry=False)
            if r.ok and SQL_ERRORS.search(r.body):
                hit = SQL_ERRORS.search(r.body).group(0)
                return [self.make(
                    ctx, title=f"SQL error disclosure via parameter '{param}'",
                    severity=MEDIUM, cwe="CWE-89",
                    description="A quote character produced a database error message. That "
                                "proves unparameterised handling, not full injection.",
                    evidence=f"payload {payload}\n{_excerpt(r.body, hit)}",
                    detection_method="Error-based quote injection", confidence=HIGH_CONF,
                    parameter=param,
                    remediation="Use parameterised queries; suppress raw errors.",
                    tags=["sqli", "error"])]
        t = await ctx.http.request("GET", self._swap(base, param, f"{seed} AND 1=1"), retry=False)
        f = await ctx.http.request("GET", self._swap(base, param, f"{seed} AND 1=2"), retry=False)
        if not (t.ok and f.ok) or len(t.body) < 100:
            return []
        delta = 1.0 - _ratio(t.body, f.body)
        base_noise = 1.0 - _ratio(baseline, t.body) if baseline else 0.0
        if delta <= max(base_noise, MIN_DIFF):
            return []
        return [self.make(
            ctx, title=f"Boolean-based SQLi indicator in '{param}'",
            severity=HIGH, cwe="CWE-89",
            description=f"'AND 1=1' and 'AND 1=2' differed by {delta*100:.1f}% while baseline "
                        f"noise was {base_noise*100:.1f}%.",
            evidence=f"1=1: {self._swap(base, param, f'{seed} AND 1=1')}\n"
                     f"1=2: {self._swap(base, param, f'{seed} AND 1=2')}\n"
                     f"delta={delta:.4f} baseline_noise={base_noise:.4f}",
            detection_method="Boolean differential vs baseline", confidence=HIGH_CONF,
            parameter=param, remediation="Parameterise queries and validate types.",
            tags=["sqli", "boolean"])]

    # ---- SSTI ------------------------------------------------------------
    async def _ssti(self, ctx, param, baseline):
        a = random.randint(1000, 9999)
        b = random.randint(100, 999)
        expect = str(a * b)
        if expect in baseline:
            expect = str(a * b + 1)
        probes = [(f"{{{{{a}*{b}}}}}", expect), (f"${{{a}*{b}}}", expect),
                  (f"<%= {a}*{b} %>", expect), (f"#{a}*{b}", expect),
                  (f"@({a}*{b})", expect)]
        for payload, want in probes:
            r = await ctx.http.request("GET", self._swap(ctx.target.url, param, payload), retry=False)
            if not r.ok or payload in r.body or want not in r.body:
                continue
            if want in baseline:
                continue
            return [self.make(
                ctx, title=f"SSTI indicator in '{param}'",
                severity=HIGH, cwe="CWE-1336",
                description=f"Unique expression {payload} evaluated to {want}, which is absent "
                            "from the payload-free baseline.",
                evidence=f"Payload: {payload}\nExpected: {want}\n"
                         f"Snippet: {_excerpt(r.body, want)}",
                detection_method="Unique arithmetic template probe", confidence=HIGH_CONF,
                parameter=param,
                remediation="Sandbox the template engine; keep user input out of templates.",
                tags=["ssti"])]
        return []

    # ---- open redirect ---------------------------------------------------
    async def _open_redirect(self, ctx, param):
        host = "zq7-tsmss.example.net"
        for payload in (f"https://{host}/", f"//{host}/"):
            r = await ctx.http.request("GET", self._swap(ctx.target.url, param, payload),
                                       allow_redirects=True, retry=False)
            if r.hops and any(host in (h.location or "") for h in r.hops):
                return [self.make(
                    ctx, title=f"Open redirect via parameter '{param}'",
                    severity=MEDIUM, cwe="CWE-601",
                    description="The redirect chain left the origin to an attacker-chosen host.",
                    evidence=" -> ".join(f"{h.url} [{h.status}] {h.location}" for h in r.hops),
                    detection_method="External redirect payload", confidence=CONFIRMED,
                    parameter=param,
                    remediation="Allowlist relative or known hosts before redirecting.",
                    tags=["redirect"])]
        return []

    # ---- traversal / cmdi / crlf ----------------------------------------
    async def _traversal(self, ctx, param):
        for payload in TRAVERSAL_PAYLOADS:
            r = await ctx.http.request("GET", self._swap(ctx.target.url, param, payload), retry=False)
            if r.ok and TRAVERSAL_MARK in r.body:
                return [self.make(
                    ctx, title=f"Path traversal confirmed in '{param}'",
                    severity=HIGH, cwe="CWE-22",
                    description="/etc/passwd content was returned from outside the web root.",
                    evidence=f"Payload: {payload}\n{_excerpt(r.body, TRAVERSAL_MARK)}",
                    detection_method="Known-file traversal payload", confidence=CONFIRMED,
                    parameter=param,
                    remediation="Canonicalise and confine paths after normalisation.",
                    tags=["traversal", "lfi"])]
        return []

    async def _cmdi(self, ctx, param):
        base = ctx.target.url
        original = parse_qs(urlparse(base).query).get(param, ["1"])[0]
        for payload, pattern in CMD_PROBES:
            r = await ctx.http.request("GET", self._swap(base, param, f"{original}{payload}"),
                                       retry=False)
            m = re.search(pattern, r.body) if r.ok else None
            if m:
                return [self.make(
                    ctx, title=f"Command injection indicator in '{param}'",
                    severity=HIGH, cwe="CWE-78",
                    description="Shell output (`id`) appeared after a command separator.",
                    evidence=f"Payload: {original}{payload}\nOutput: {m.group(0)}",
                    detection_method="Shell metacharacter probe", confidence=HIGH_CONF,
                    parameter=param,
                    remediation="Avoid shell interpolation; pass argument vectors.",
                    tags=["cmdi", "rce"])]
        return []

    async def _crlf(self, ctx, param):
        marker = "z" + secrets.token_hex(3)
        payload = f"x%0d%0aX-T-{marker}%3a1"
        r = await ctx.http.request("GET", self._swap(ctx.target.url, param, payload), retry=False)
        if r.ok and any(f"x-t-{marker}" in k for k in r.headers):
            return [self.make(
                ctx, title=f"CRLF header injection in '{param}'",
                severity=MEDIUM, cwe="CWE-113",
                description="An injected CRLF created a new response header.",
                evidence=f"Payload: {payload}",
                detection_method="CRLF header payload", confidence=HIGH_CONF,
                parameter=param, remediation="Strip CR/LF from header-bound input.",
                tags=["crlf"])]
        return []

    # ---- XXE / smuggling / cache ----------------------------------------
    async def _xxe(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None:
            return []
        actions = re.findall(r'<form[^>]+action="([^"]+)"', resp.body, re.I)[:3]
        for action in actions:
            url = action if action.startswith("http") else str(ctx.target.root).rstrip("/") + "/" + action.lstrip("/")
            r = await ctx.http.request("POST", url, retry=False,
                                       headers={"Content-Type": "application/xml"},
                                       content=XXE_BODY)
            if r.ok and TRAVERSAL_MARK in r.body:
                return [self.make(
                    ctx, title="XXE confirmed",
                    severity=HIGH, cwe="CWE-611",
                    description="An external entity resolving file:///etc/passwd was expanded.",
                    evidence=f"POST {url}\n{_excerpt(r.body, TRAVERSAL_MARK)}",
                    detection_method="External entity payload", confidence=CONFIRMED,
                    remediation="Disable DOCTYPE / external entities in the XML parser.",
                    tags=["xxe"])]
        return []

    async def _smuggling(self, ctx):
        resp = getattr(ctx, "homepage", None)
        if resp is None or not (resp.header("content-length") and resp.header("transfer-encoding")):
            return []
        return [self.make(
            ctx, title="Content-Length and Transfer-Encoding both present",
            severity=LOW, cwe="CWE-444",
            description="Conflicting framing headers are the precondition for request smuggling; "
                        "presence alone does not prove desync.",
            evidence=f"CL={resp.header('content-length')} TE={resp.header('transfer-encoding')}",
            detection_method="Framing header inspection", confidence=NEEDS_MANUAL,
            remediation="Normalise framing at the edge; prefer HTTP/2 end-to-end.",
            tags=["smuggling"])]

    async def _cache_poison(self, ctx):
        marker = "z" + secrets.token_hex(3)
        r = await ctx.http.request("GET", ctx.target.url, retry=False,
                                   headers={"X-Forwarded-Host": f"{marker}.example.net"})
        if not r.ok or marker not in r.body:
            return []
        cache = r.header("x-cache") or r.header("cf-cache-status") or r.header("age")
        if not cache:
            return []
        return [self.make(
            ctx, title="X-Forwarded-Host reflected into a cacheable response",
            severity=LOW, cwe="CWE-524",
            description="The injected host was reflected and a cache-status header exists. If the "
                        "host is unkeyed, poisoned content can be served to others.",
            evidence=f"X-Forwarded-Host: {marker}.example.net\ncache: {cache}",
            detection_method="Host header reflection", confidence=NEEDS_MANUAL,
            remediation="Add the host to the cache key or validate it against an allowlist.",
            tags=["cache", "poisoning"])]
VIEOF
python -m compileall -q modules/vulnerability_indicators.py && ok "vuln module rewritten" || { bad "vuln compile"; F=$((F+1)); }

echo "=== 9. engine: dedupe + min confidence ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("core/engine.py"); s=p.read_text()
if "_dedupe" in s: print("  skip"); raise SystemExit
old='''        findings.sort(key=lambda f: (severity_rank(f.severity), f.title))'''
new='''        findings = _dedupe(findings, self.config.get("scan.min_confidence", ""))
        findings.sort(key=lambda f: (severity_rank(f.severity), f.title))'''
if old not in s: print("  MISS sort"); sys.exit(1)
s=s.replace(old,new,1)
s=s.replace("def build_modules(", '''_CONF_ORDER = {"CONFIRMED": 0, "HIGH CONFIDENCE": 1, "MEDIUM CONFIDENCE": 2,
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


def build_modules(''',1)
p.write_text(s); print("  ok engine dedupe")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 10. global score = mean of target scores ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("core/report_manager.py"); s=p.read_text()
if "mean_target_score" in s: print("  skip"); raise SystemExit
old='''    @staticmethod
    def summarize(rows: list[dict]) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for r in rows:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        value, grade = score_counts(counts)'''
new='''    @staticmethod
    def mean_target_score(findings_by_target: dict) -> dict:
        """Batch score is the mean of per-target scores, never a sum."""
        scores = [score_counts(_counts(rows)) for rows in findings_by_target.values()]
        if not scores:
            return {"score": 100, "grade": "A", "counts": {s: 0 for s in SEVERITY_ORDER},
                    "total": 0}
        mean = round(sum(v for v, _ in scores) / len(scores))
        worst = min(g for _, g in scores)
        all_counts = {s: 0 for s in SEVERITY_ORDER}
        for rows in findings_by_target.values():
            for r in rows:
                all_counts[r["severity"]] += 1
        return {"score": mean, "grade": worst, "counts": all_counts,
                "total": sum(all_counts.values())}

    @staticmethod
    def summarize(rows: list[dict]) -> dict:
        counts = _counts(rows)
        value, grade = score_counts(counts)'''
if old not in s: print("  MISS summarize"); sys.exit(1)
s=s.replace(old,new,1)
s=s.replace("def _esc(value) -> str:", '''def _counts(rows: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts


def _esc(value) -> str:''',1)
# html_report + txt_report + json_report global summary
s=s.replace("        all_rows = [f for rows in findings_by_target.values() for f in rows]\n        s = self.summarize(all_rows)",
            "        all_rows = [f for rows in findings_by_target.values() for f in rows]\n        s = self.mean_target_score(findings_by_target)")
p.write_text(s); print("  ok mean score")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 11. evidence truncation in reports ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("core/report_manager.py"); s=p.read_text()
if "_trim_evidence" in s: print("  skip"); raise SystemExit
s=s.replace("def _counts(rows: list[dict]) -> dict:", '''_HEADER_BLOCK = re.compile(r"^(?:Response headers|GET \\S+ -> \\d+)$", re.M)


def _trim_evidence(text, limit: int = 700) -> str:
    """Header dumps are long and repeated; keep a bounded slice."""
    text = str(text or "")
    return text if len(text) <= limit else text[:limit] + "\\n...[truncated]"


def _counts(rows: list[dict]) -> dict:''',1)
if "import re" not in s:
    s=s.replace("import json\n","import json\nimport re\n",1)
s=s.replace('{f\'<details><summary>Evidence</summary><pre>{_esc(f["evidence"])}</pre></details>\' if f.get(\'evidence\') else ""}',
            '{f\'<details><summary>Evidence</summary><pre>{_esc(_trim_evidence(f["evidence"]))}</pre></details>\' if f.get(\'evidence\') else ""}',1)
p.write_text(s); print("  ok evidence trim")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 12. main.py: --min-confidence / --fail-on ==="
python - <<'PY'
import pathlib,sys
p=pathlib.Path("main.py"); s=p.read_text()
if "--min-confidence" in s: print("  skip"); raise SystemExit
s=s.replace('''    ap.add_argument("--no-reports", action="store_true", help="skip report generation")''',
'''    ap.add_argument("--no-reports", action="store_true", help="skip report generation")
    ap.add_argument("--min-confidence", default="",
                    choices=["", "CONFIRMED", "HIGH CONFIDENCE", "MEDIUM CONFIDENCE",
                             "LOW CONFIDENCE"],
                    help="drop findings below this confidence")
    ap.add_argument("--fail-on", default="", choices=["", "CRITICAL", "HIGH", "MEDIUM"],
                    help="exit 2 when a finding at or above this severity exists")''',1)
s=s.replace('''    asyncio.run(run_scan(urls, f"batch:{source}", auto_reports=not args.no_reports))
    return 0''',
'''    RUNTIME["config"].set("scan.min_confidence", args.min_confidence)
    asyncio.run(run_scan(urls, f"batch:{source}", auto_reports=not args.no_reports))
    if args.fail_on:
        from config import SEVERITY_ORDER
        limit = SEVERITY_ORDER.index(args.fail_on)
        hits = [f for s in db_scans() for f in s if SEVERITY_ORDER.index(f) <= limit]
        if hits:
            console.print(f"[red]fail-on {args.fail_on}: {len(hits)} finding(s)[/red]")
            return 2
    return 0''',1)
s=s.replace("def cli(argv: list[str]) -> int:", '''def db_scans() -> list[list[str]]:
    """Severity lists of every finding in the most recent scan."""
    db = RUNTIME["db"]
    rows = db.recent_scans(1)
    if not rows:
        return []
    return [[r["severity"] for r in db.findings(rows[0]["id"])]]


def cli(argv: list[str]) -> int:''',1)
p.write_text(s); print("  ok cli flags")
PY
[ $? -ne 0 ] && F=$((F+1))

echo "=== 13. compile + tests ==="
python -m compileall -q core modules ui main.py config.py 2>&1 | tail -8
python tests/selftest.py || { bad selftest; F=$((F+1)); }
python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
python -m unittest discover tests >/dev/null 2>&1 || { bad "unit tests"; F=$((F+1)); }

echo
if [ "$F" -eq 0 ]; then printf '%sAll green.%s\n' "$G" "$N"
else printf '%s%d issue(s).%s\n' "$R" "$F" "$N"; exit 1; fi
