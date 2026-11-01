#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. validator: strip invisible unicode ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/validator.py")
s = p.read_text()

old = '''def normalize(raw: str) -> str:
    s = (raw or "").strip()'''
new = '''# Invisible characters that survive copy-paste from browsers, chat apps and
# PDFs. They are not whitespace, so .strip() alone will not remove them.
_INVISIBLE = str.maketrans("", "", "\\u200b\\u200c\\u200d\\u200e\\u200f\\u2060"
                                 "\\ufeff\\u00a0\\u2028\\u2029\\u00ad")


def _clean(raw: str) -> str:
    return (raw or "").translate(_INVISIBLE)


def normalize(raw: str) -> str:
    s = _clean(raw).strip()'''

if "_INVISIBLE = str.maketrans" in s:
    print("  skip validator (already applied)")
elif old not in s:
    print("  MISS normalize anchor"); sys.exit(1)
else:
    s = s.replace(old, new, 1)
    old_v = '''def validate(raw: str) -> ValidationResult:
    if not (raw or "").strip():'''
    new_v = '''def validate(raw: str) -> ValidationResult:
    raw = _clean(raw)
    if not raw.strip():'''
    if old_v not in s:
        print("  MISS validate anchor"); sys.exit(1)
    s = s.replace(old_v, new_v, 1)
    s = s.replace('f"invalid hostname \'{host}\'"', 'f"invalid hostname {host!r}"', 1)
    p.write_text(s)
    print("  ok   invisible chars stripped")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 2. main.py: admitted must be strings, blocked must be pairs ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("main.py")
s = p.read_text()
old = '''    admitted, blocked = [], []
    for u in urls:
        decision = scope.check_target(u)
        (admitted if decision.allowed else blocked).append((u, decision.reason))'''
new = '''    admitted: list[str] = []
    blocked: list[tuple[str, str]] = []
    for u in urls:
        decision = scope.check_target(u)
        if decision.allowed:
            admitted.append(u)
        else:
            blocked.append((u, decision.reason))'''
if "admitted: list[str] = []" in s:
    print("  skip main.py (already applied)")
elif old not in s:
    print("  MISS main.py anchor"); sys.exit(1)
else:
    p.write_text(s.replace(old, new, 1))
    print("  ok   admitted holds plain URLs")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. regression test for invisible characters ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_core.py")
s = p.read_text()
if "test_strips_invisible_characters" in s:
    print("  skip test (already applied)")
else:
    block = '''    def test_strips_invisible_characters(self):
        for junk in ("\\u200e", "\\u200b", "\\ufeff", "\\u00a0", "\\u00ad", "\\u200f"):
            self.assertEqual(normalize(f"{junk}https://example.com/"),
                             "https://example.com/", repr(junk))
            self.assertTrue(validate(f"{junk}https://example.com/").valid, repr(junk))

'''
    anchor = "    def test_dedupe(self):"
    if anchor not in s:
        print("  MISS test anchor"); sys.exit(1)
    p.write_text(s.replace(anchor, block + anchor, 1))
    print("  ok   regression test added")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. compile + tests ==="
python -m compileall -q core modules ui main.py config.py 2>&1 | tail -5
python tests/selftest.py || { bad "selftest"; FAILED=$((FAILED+1)); }
python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
python -m unittest discover tests >/dev/null 2>&1 || { bad "unit tests"; FAILED=$((FAILED+1)); }

echo "=== 5. re-validate your real targets.txt ==="
python - <<'PYEOF'
import sys
sys.path.insert(0, ".")
from core.validator import load_targets
urls, rej = load_targets("targets.txt")
real = [r for r in rej if not str(r["raw"]).startswith("#")]
print(f"  valid   : {len(urls)}")
print(f"  rejected: {len(real)}")
for r in real[:10]:
    print(f"    line {r['line']}: {r['reason']}")
PYEOF

echo
if [ "$FAILED" -eq 0 ]; then printf '%sAll green.%s\n' "$G" "$N"
else printf '%s%d issue(s).%s\n' "$R" "$FAILED" "$N"; exit 1; fi
