#!/usr/bin/env bash
# TSMSS repair script — idempotent. Run from repo root: bash fix.sh
set -uo pipefail
cd "$(dirname "$0")" || exit 1

G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s MISS %s%s\n' "$R" "$N" "$*"; }
warn(){ printf '%s warn %s%s\n' "$Y" "$N" "$*"; }
FAILED=0

echo "=== 1. relocate modules/ ==="
if [ -d core/modules ] && [ ! -d modules ]; then
  if git mv core/modules modules 2>/dev/null || mv core/modules modules; then
    ok "core/modules -> modules"
  else
    bad "could not move core/modules"; FAILED=$((FAILED+1))
  fi
elif [ -d modules ]; then
  ok "modules/ already at root"
  [ -d core/modules ] && warn "stale core/modules still present" && rm -rf core/modules
else
  bad "no module directory found"; FAILED=$((FAILED+1))
fi

echo "=== 2. config files ==="
mkdir -p config
if [ ! -f config/settings.example.yaml ]; then
cat > config/settings.example.yaml <<'YEOF'
# TSMSS settings. Copy to settings.yaml (installer does this for you).
scan:
  concurrency_targets: 3
  max_requests_per_second: 4.0
  per_host_requests_per_second: 1.5
  request_timeout: 20
  max_retries: 3
  retry_backoff: 1.6
  max_redirects: 5
  target_timeout: 900
  module_timeout: 120
  batch_size: 5
  delay_between_requests: 0.12
  max_response_bytes: 1048576
  user_agent: "TSMSS/1.0 (+authorized-security-audit; Termux)"
scope:
  authorized: false
  allow_private_targets: false
  allow_subdomains: true
  allow_out_of_scope_redirects: false
  allowed_domains: []
  max_targets: 500
active:
  xss: true
  sqli: true
  ssti: true
  open_redirect: true
  path_traversal: true
  command_injection: true
  crlf: true
  xxe: true
  ldap: true
  subdomain_takeover: true
  smuggling: true
  cache_poisoning: true
  param_discovery: true
  max_params_per_target: 25
  max_payloads_per_param: 4
dns:
  resolvers: ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
  timeout: 6
  lifetime: 12
infra:
  enable_nmap: true
  nmap_ports: "80,443,8080,8443,8000,3000,5000"
  nmap_host_timeout: "90s"
  enable_whois: true
  enable_go_tools: true
safety:
  require_authorization: true
  max_total_requests_per_target: 900
  pause_on_battery_below: 10
  check_battery: true
  notify_on_complete: true
reporting:
  open_html_on_finish: false
  include_response_bodies: true
  evidence_max_bytes: 8192
logging:
  level: INFO
  audit_log: true
YEOF
ok "config/settings.example.yaml created"
else ok "config/settings.example.yaml exists"; fi

if [ ! -f config/rules.yaml ]; then
cat > config/rules.yaml <<'REOF'
# Header rule overrides. Empty mapping = use the built-in defaults.
# Example:
# headers:
#   content-security-policy:
#     severity: LOW
#     title: "CSP absent (accepted risk)"
#     description: "Tracked in RISK-114."
#     remediation: "Planned for Q2."
headers: {}
REOF
ok "config/rules.yaml created"
else ok "config/rules.yaml exists"; fi

[ -f config/settings.yaml ] || { cp config/settings.example.yaml config/settings.yaml && ok "config/settings.yaml created"; }

echo "=== 3. targets.txt ==="
if [ ! -f targets.txt ]; then
  printf '# TSMSS targets - one authorized URL per line\n# https://example.com\n' > targets.txt
  ok "targets.txt created"
else ok "targets.txt exists"; fi

echo "=== 4. .gitignore runtime block ==="
if ! grep -q 'TSMSS runtime' .gitignore 2>/dev/null; then
  cat >> .gitignore <<'GEOF'

# TSMSS runtime
database/*.db
database/*.db-*
logs/*.log
reports/
config/settings.yaml
GEOF
  ok "runtime ignores added"
else ok "runtime ignores present"; fi

echo "=== 5. python patches ==="
python - <<'PYEOF'
import pathlib, sys

failed = []

def patch(path, old, new, label):
    p = pathlib.Path(path)
    if not p.exists():
        failed.append(f"{label}: {path} missing"); return
    s = p.read_text()
    if old not in s:
        if new in s:
            print(f"  skip {label} (already applied)")
        else:
            failed.append(f"{label}: anchor not found in {path}")
        return
    p.write_text(s.replace(old, new, 1))
    print(f"  ok   {label}")

# --- main.py: Finding reconstruction crash -------------------------------
patch("main.py",
"""    rows = [dict(r) for r in db.findings(scan_id)]
    targets = [dict(t) for t in db.targets(scan_id)]
    overall, grade = score([])
    from core.finding import Finding
    findings_objs = [Finding(**{k: v for k, v in r.items()
                               if k in Finding.__dataclass_fields__}) for r in rows]
    overall, grade = score(findings_objs)""",
"""    rows = [dict(r) for r in db.findings(scan_id)]
    targets = [dict(t) for t in db.targets(scan_id)]
    from core.finding import Finding
    findings_objs = []
    for r in rows:
        data = {k: v for k, v in r.items() if k in Finding.__dataclass_fields__}
        data["target"] = r["target_url"]
        findings_objs.append(Finding(**data))
    overall, grade = score(findings_objs)""",
"main.py Finding(target=...)")

# --- main.py: dead `failed` variable -------------------------------------
patch("main.py",
"""        _, findings, extra, error, requests = result
        failed = bool(error) or extra == 0 and not findings
        # `extra` carries either a grade letter or an error string
        grade_like = isinstance(extra, str) and extra in list("ABCDEF")""",
"""        _, findings, extra, error, requests = result
        # `extra` carries a grade letter on success, an error string on failure
        grade_like = isinstance(extra, str) and extra in tuple("ABCDEF")""",
"main.py on_done")

# --- main.py: unused imports --------------------------------------------
patch("main.py", "from rich.console import Console\n", "", "main.py unused Console")
patch("main.py", "from core.scheduler import BatchState, Scheduler",
      "from core.scheduler import Scheduler", "main.py unused BatchState")

# --- engine.py: unused import -------------------------------------------
patch("core/engine.py", "from urllib.parse import urlsplit\n", "", "engine.py unused urlsplit")

# --- http_security.py: nonsense expression ------------------------------
patch("modules/http_security.py", "severity=HIGH_CONF and MEDIUM", "severity=MEDIUM",
      "http_security severity")

# --- http_client.py: real Set-Cookie list -------------------------------
patch("core/http_client.py",
"""    truncated: bool = False
    error: str | None = None""",
"""    truncated: bool = False
    set_cookies: list[str] = field(default_factory=list)
    error: str | None = None""",
"Fetched.set_cookies field")

patch("core/http_client.py",
"""                fetched = Fetched(url, resp.status_code, headers, body, elapsed,
                                  final_url=str(resp.url))""",
"""                fetched = Fetched(url, resp.status_code, headers, body, elapsed,
                                  final_url=str(resp.url),
                                  set_cookies=resp.headers.get_list("set-cookie"))""",
"populate set_cookies")

patch("core/http_client.py",
"""                fetched.headers = headers
                fetched.body = await self._read_body(resp)""",
"""                fetched.headers = headers
                fetched.set_cookies = resp.headers.get_list("set-cookie")
                fetched.body = await self._read_body(resp)""",
"populate set_cookies on redirect")

# --- cookies.py: duplicate findings -------------------------------------
patch("modules/cookies.py",
"""        for raw in resp.get_all("set-cookie") + self._multi(resp):
            out += self._review(ctx, raw, resp)""",
"""        for raw in resp.set_cookies:
            out += self._review(ctx, raw, resp)""",
"cookies iterate set_cookies")

patch("modules/cookies.py",
"""    @staticmethod
    def _multi(resp) -> list[str]:
        val = resp.header("set-cookie")
        return [] if not val else [val]

""", "", "cookies drop _multi")

# --- tests: dead assertion + fake client -------------------------------
patch("tests/test_modules.py",
"""            self.assertIn("Content-Security-Policy", titles)
            self.assertIn("X-Frame-Options", titles) if False else None
            self.assertIn("clickjacking", titles.lower())""",
"""            self.assertIn("Content-Security-Policy", titles)
            self.assertIn("clickjacking", titles.lower())""",
"test dead assertion")

patch("tests/test_modules.py",
"""            return Fetched(u, r.status_code, {k.lower(): v for k, v in r.headers.items()},
                           r.text, 1.0, hops=hops, final_url=str(r.url))""",
"""            return Fetched(u, r.status_code, {k.lower(): v for k, v in r.headers.items()},
                           r.text, 1.0, hops=hops, final_url=str(r.url),
                           set_cookies=r.headers.get_list("set-cookie"))""",
"fake client set_cookies")

# --- selftest: meaningful private-IP test ------------------------------
patch("tests/selftest.py",
"""    g = ScopeGuard(["localhost"], allow_private=False)
    assert not g.check_target("http://127.0.0.1/").allowed""",
"""    g = ScopeGuard(["127.0.0.1"], allow_private=False)
    assert not g.check_target("http://127.0.0.1/").allowed""",
"selftest private-ip")

# --- installer.sh: pip import map --------------------------------------
patch("installer.sh",
"""hdr "5. Python packages"
python -m pip install --upgrade pip >/dev/null 2>&1
while IFS= read -r line; do
  [ -z "$line" ] && continue; case "$line" in \\#*) continue ;; esac
  pkgname="${line%%[<>=]*}"
  python -c "import ${pkgname//-/_}" 2>/dev/null && { ok "$pkgname present"; continue; }""",
"""hdr "5. Python packages"
declare -A IMPORTS=([beautifulsoup4]=bs4 [PyYAML]=yaml [dnspython]=dns [httpx]=httpx [rich]=rich)
python -m pip install --upgrade pip >/dev/null 2>&1
while IFS= read -r line; do
  [ -z "$line" ] && continue; case "$line" in \\#*) continue ;; esac
  pkgname="${line%%[<>=]*}"
  mod="${IMPORTS[$pkgname]:-${pkgname//-/_}}"
  python -c "import $mod" 2>/dev/null && { ok "$pkgname present"; continue; }""",
"installer pip import map")

# --- installer.sh: config bootstrap ------------------------------------
patch("installer.sh",
"""hdr "7. Config bootstrap"
[ -f config/settings.yaml ] || cp config/settings.example.yaml config/settings.yaml 2>/dev/null && ok "settings.yaml"
[ -f targets.txt ] || { printf '# one authorized URL per line\\nhttps://example.com\\n' > targets.txt; ok "targets.txt"; }""",
"""hdr "7. Config bootstrap"
if [ ! -f config/settings.yaml ]; then
  if cp config/settings.example.yaml config/settings.yaml 2>/dev/null; then
    ok "settings.yaml created"
  else
    warn "settings.example.yaml missing - defaults will be used"
  fi
else
  ok "settings.yaml kept"
fi
[ -f targets.txt ] || { printf '# one authorized URL per line\\nhttps://example.com\\n' > targets.txt; ok "targets.txt"; }""",
"installer config bootstrap")

# --- installer.sh: self-test guard -------------------------------------
patch("installer.sh",
"""hdr "9. Self-test"
python -m compileall""",
"""hdr "9. Self-test"
[ -d modules ] || { err "modules/ missing at repo root"; FAILED=$((FAILED+1)); }
python -m compileall""",
"installer selftest guard")

if failed:
    print("\nFAILURES:")
    for f in failed:
        print("  -", f)
    sys.exit(1)
print("\nall patches applied")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 6. clear bytecode ==="
find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null
ok "bytecode cleared"

echo "=== 7. verify ==="
if python -m compileall -q core modules ui main.py config.py 2>/dev/null; then
  ok "sources compile"
else
  bad "compile errors"; FAILED=$((FAILED+1))
fi
if python tests/selftest.py; then
  ok "selftest passed"
else
  bad "selftest failed"; FAILED=$((FAILED+1))
fi

echo
if [ "$FAILED" -eq 0 ]; then
  printf '%sAll fixes applied and verified.%s\n' "$G" "$N"
  printf 'Next: bash installer.sh   then   python main.py\n'
else
  printf '%s%d problem(s) remain - read the MISS lines above.%s\n' "$R" "$FAILED" "$N"
  exit 1
fi
