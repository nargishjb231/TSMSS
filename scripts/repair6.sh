#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
warn(){ printf '%s warn %s%s\n' "$Y" "$N" "$*"; }
FAILED=0

echo "=== 1. diagnostics: /tmp ==="
ls -ld /tmp 2>&1 || warn "/tmp does not exist"
if printf 'probe' > /tmp/.tsmss_probe 2>/dev/null; then
  ok "/tmp writable"
  rm -f /tmp/.tsmss_probe
else
  warn "/tmp NOT writable"
fi
python - <<'PYEOF'
import tempfile, traceback
try:
    with tempfile.TemporaryDirectory() as d:
        print("  ok   tempfile works:", d)
except Exception:
    print("  MISS tempfile fails:")
    traceback.print_exc()
PYEOF

echo "=== 2. tracebacks of the two failing tests ==="
python -m unittest tests.test_core.TestEvidence.test_truncation_and_dedupe \
                tests.test_core.TestValidator.test_dedupe 2>&1 | tail -40

echo "=== 3. move both tests off the global temp dir ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_core.py")
s = p.read_text()

old_dedupe = '''    def test_dedupe(self):
        p = Path("/tmp/t.txt")
        p.write_text("example.com\\nhttps://example.com/\\n# c\\n\\nbad host\\n")
        ok, rej = load_targets(p)
        self.assertEqual(ok, ["https://example.com/"])
        self.assertTrue(any(r["reason"] == "duplicate" for r in rej))'''
new_dedupe = '''    def test_dedupe(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            p = Path(d) / "t.txt"
            p.write_text("example.com\\nhttps://example.com/\\n# c\\n\\nbad host\\n")
            ok, rej = load_targets(p)
        self.assertEqual(ok, ["https://example.com/"])
        self.assertTrue(any(r["reason"] == "duplicate" for r in rej))'''

old_ev = '''        import tempfile
        with tempfile.TemporaryDirectory() as d:
            es = EvidenceStore(Path(d), max_bytes=20)'''
new_ev = '''        import tempfile
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            es = EvidenceStore(Path(d), max_bytes=20)'''

changed = False
if "TemporaryDirectory(dir=Path(__file__).resolve().parent)" in s:
    print("  skip test_core.py (already applied)")
else:
    if old_dedupe in s:
        s = s.replace(old_dedupe, new_dedupe, 1); changed = True
    else:
        print("  MISS test_dedupe anchor"); sys.exit(1)
    if old_ev in s:
        s = s.replace(old_ev, new_ev, 1); changed = True
    else:
        print("  MISS evidence anchor"); sys.exit(1)
    if changed:
        p.write_text(s)
        print("  ok   tests use repo-local temp dirs")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. re-run those two tests ==="
if python -m unittest tests.test_core.TestEvidence.test_truncation_and_dedupe \
                     tests.test_core.TestValidator.test_dedupe -v 2>&1 | tail -20; then
  ok "both tests pass"
else
  bad "still failing"; FAILED=$((FAILED+1))
fi

echo "=== 5. full suite ==="
python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
python -m unittest discover tests >/dev/null 2>&1
RC=$?
[ "$RC" -ne 0 ] && { bad "unit tests rc=$RC"; FAILED=$((FAILED+1)); }

echo "=== 6. selftest ==="
python tests/selftest.py || { bad "selftest"; FAILED=$((FAILED+1)); }

echo
if [ "$FAILED" -eq 0 ]; then
  printf '%sAll green.%s\n' "$G" "$N"
else
  printf '%s%d issue(s) remain.%s\n' "$R" "$FAILED" "$N"; exit 1
fi
