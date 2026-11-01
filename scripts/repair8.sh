#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. EvidenceStore: derive prefix from its own directory name ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/evidence.py")
s = p.read_text()

old_doc = '''    def save(self, label: str, body: str, kind: str = "txt") -> str:
        """Persist truncated evidence, return a repo-relative path or inline snippet."""'''
new_doc = '''    def save(self, label: str, body: str, kind: str = "txt") -> str:
        """Persist truncated evidence.

        Returns a path relative to the store's parent directory, e.g.
        ``evidence/<label>_<digest>.txt``. The prefix is taken from this
        store's own directory name so the value stays correct whichever
        directory the caller mounts. Falls back to an inline snippet when
        the file cannot be written.
        """'''
old_pref = "        self._seen: dict[str, str] = {}"
new_pref = ("        self._seen: dict[str, str] = {}\n"
            "        # prefix returned by save(); must mirror the real folder name\n"
            "        self._prefix = self.dir.name or \"evidence\"")

if "self._prefix = self.dir.name" in s:
    print("  skip prefix (already applied)")
elif old_pref not in s or old_doc not in s:
    print("  MISS evidence anchor"); sys.exit(1)
else:
    s = s.replace(old_doc, new_doc, 1).replace(old_pref, new_pref, 1)
    s = s.replace('self._seen[slot] = f"evidence/{path.name}"',
                  'self._seen[slot] = f"{self._prefix}/{path.name}"', 1)
    p.write_text(s)
    print("  ok   prefix derived from directory")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 2. test: mount the store on an 'evidence' subdir ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_core.py")
s = p.read_text()
old = '''            es = EvidenceStore(Path(d), max_bytes=20)
            a = es.save("lbl", "x" * 100)
            b = es.save("lbl", "x" * 100)
            self.assertEqual(a, b)
            files = sorted((Path(d) / "evidence").glob("*.txt"))
            self.assertEqual(len(files), 1, f"expected 1 deduped file, got {len(files)}")
            self.assertIn("truncated", files[0].read_text())'''
new = '''            ev = Path(d) / "evidence"
            es = EvidenceStore(ev, max_bytes=20)
            a = es.save("lbl", "x" * 100)
            b = es.save("lbl", "x" * 100)
            self.assertEqual(a, b, "repeat save must return the identical path")
            self.assertTrue(a.startswith("evidence/"), a)
            files = sorted(ev.glob("*.txt"))
            self.assertEqual(len(files), 1, f"expected 1 deduped file, got {len(files)}")
            self.assertIn("truncated", files[0].read_text())'''
if "ev = Path(d) / \"evidence\"" in s:
    print("  skip test (already applied)")
elif old not in s:
    print("  MISS test anchor"); sys.exit(1)
else:
    p.write_text(s.replace(old, new, 1))
    print("  ok   test mounts evidence subdir")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. evidence test ==="
python -m unittest tests.test_core.TestEvidence.test_truncation_and_dedupe -v 2>&1 | tail -12
python -m unittest tests.test_core.TestEvidence.test_truncation_and_dedupe >/dev/null 2>&1 \
  || { bad "evidence test"; FAILED=$((FAILED+1)); }

echo "=== 4. compile + selftest + full suite ==="
python -m compileall -q core modules ui main.py config.py 2>&1 | tail -5
python tests/selftest.py || { bad "selftest"; FAILED=$((FAILED+1)); }
python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
python -m unittest discover tests >/dev/null 2>&1
RC=$?
[ "$RC" -ne 0 ] && { bad "unit tests rc=$RC"; FAILED=$((FAILED+1)); }

echo
if [ "$FAILED" -eq 0 ]; then
  printf '%sAll green.%s\n' "$G" "$N"
else
  printf '%s%d issue(s) remain.%s\n' "$R" "$FAILED" "$N"; exit 1
fi
