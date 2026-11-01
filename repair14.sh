#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. config: modules.disabled ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("config.py")
s = p.read_text()
if '"modules"' in s:
    print("  skip config.py (already applied)")
else:
    anchor = '    "tools": {'
    if anchor not in s:
        print("  MISS config anchor"); sys.exit(1)
    s = s.replace(anchor, '    "modules": {"disabled": []},\n' + anchor, 1)
    p.write_text(s)
    print("  ok   modules.disabled added")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 2. engine honours it ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/engine.py")
s = p.read_text()
if "skip_modules" in s:
    print("  skip engine (already applied)")
else:
    old = "def build_modules(rules: dict) -> list:"
    new = "def build_modules(rules: dict, disabled=None) -> list:"
    if old not in s:
        print("  MISS build_modules anchor"); sys.exit(1)
    s = s.replace(old, new, 1)
    old2 = "    return [registry[name]() for name in MODULE_ORDER if name in registry]"
    new2 = ("    skip_modules = set(disabled or [])\n"
            "    return [registry[name]() for name in MODULE_ORDER\n"
            "            if name in registry and name not in skip_modules]")
    if old2 not in s:
        print("  MISS return anchor"); sys.exit(1)
    s = s.replace(old2, new2, 1)
    old3 = "        self.modules = build_modules(rules)"
    new3 = ("        self.disabled_modules = list(config.get(\"modules.disabled\", []) or [])\n"
            "        self.modules = build_modules(rules, self.disabled_modules)")
    if old3 not in s:
        print("  MISS init anchor"); sys.exit(1)
    s = s.replace(old3, new3, 1)
    p.write_text(s)
    print("  ok   disabled modules filtered")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. smoke test: skip network-bound modules ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_scan_smoke.py")
s = p.read_text()
if "modules.disabled" in s:
    print("  skip smoke test (already applied)")
else:
    old = '        cfg.set("infra.enable_whois", False)'
    new = ('        cfg.set("infra.enable_whois", False)\n'
           '        # 127.0.0.1 has no meaningful DNS/TLS; keep the test fast\n'
           '        cfg.set("modules.disabled", ["dns_security", "ssl_tls", "infrastructure"])\n'
           '        cfg.set("scan.module_timeout", 10)\n'
           '        cfg.set("scan.request_timeout", 5)')
    if old not in s:
        print("  MISS smoke anchor"); sys.exit(1)
    p.write_text(s.replace(old, new, 1))
    print("  ok   smoke test scoped")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. settings example ==="
grep -q '^modules:' config/settings.example.yaml 2>/dev/null \
  || printf '\nmodules:\n  disabled: []\n' >> config/settings.example.yaml

echo "=== 5. selftest (must stay >= 13 modules) ==="
python tests/selftest.py || { bad selftest; FAILED=$((FAILED+1)); }

echo "=== 6. smoke test alone, timed ==="
time timeout 180 python -m unittest tests.test_scan_smoke -v 2>&1 | tail -15
RC=${PIPESTATUS[0]}
[ "$RC" -ne 0 ] && { bad "smoke test rc=$RC"; FAILED=$((FAILED+1)); }

echo "=== 7. full suite, hard timeout ==="
timeout 400 python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
timeout 400 python -m unittest discover tests >/dev/null 2>&1 \
  && ok "full suite" || { bad "full suite"; FAILED=$((FAILED+1)); }

echo
if [ "$FAILED" -eq 0 ]; then printf '%sAll green.%s\n' "$G" "$N"
else printf '%s%d issue(s).%s\n' "$R" "$FAILED" "$N"; exit 1; fi
