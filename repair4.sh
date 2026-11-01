#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. Target.root must be a string ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/context.py")
s = p.read_text()
old = """    @property
    def root(self):
        return self.parts._replace(path="/", query="", fragment="")
"""
new = """    @property
    def root(self) -> str:
        \"\"\"Origin URL as a string, always ending in a single '/'.

        Callers do str(target.root) and concatenate paths, so this must never
        return a SplitResult (whose str() is a repr).
        \"\"\"
        return self.parts._replace(path="/", query="", fragment="").geturl()
"""
if "def root(self) -> str:" in s:
    print("  skip context.py (already applied)")
elif old not in s:
    print("  MISS context.py anchor"); sys.exit(1)
else:
    p.write_text(s.replace(old, new, 1))
    print("  ok   root returns str")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 2. fixture SQL sink matches real payload ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_modules.py")
s = p.read_text()
old = """            if q == "boom'":
                return self._send(500, b"SQL syntax error near '''")"""
new = """            if q.endswith("'"):
                return self._send(500, b"<html>SQL syntax error near '''</html>")"""
if 'q.endswith("\'")' in s:
    print("  skip fixture (already applied)")
elif old not in s:
    print("  MISS fixture anchor"); sys.exit(1)
else:
    p.write_text(s.replace(old, new, 1))
    print("  ok   fixture sql sink")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. debug-param query join ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("modules/information_disclosure.py")
s = p.read_text()
old = """        for param, value in (("?debug=1", None), ("?test=1", None), ("?_profiler=1", None)):
            resp = await ctx.http.request("GET", ctx.target.url + param, retry=False)"""
new = """        sep = "&" if "?" in ctx.target.url else "?"
        for param, value in (("debug=1", None), ("test=1", None), ("_profiler=1", None)):
            probe = ctx.target.url + sep + param
            resp = await ctx.http.request("GET", probe, retry=False)"""
if "sep = \"&\" if \"?\" in ctx.target.url" in s:
    print("  skip debug params (already applied)")
elif old not in s:
    print("  MISS debug param anchor"); sys.exit(1)
else:
    s = s.replace(old, new, 1)
    s = s.replace('evidence=f"GET {ctx.target.url + param} -> {resp.status}\\n{resp.body[:400]}"',
                  'evidence=f"GET {probe} -> {resp.status}\\n{resp.body[:400]}"')
    p.write_text(s)
    print("  ok   debug param join")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. regression tests for Target ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_core.py")
s = p.read_text()
if "class TestTarget" in s:
    print("  skip test_core.py (already applied)")
else:
    s = s.replace("from core.evidence import EvidenceStore\n",
                  "from core.evidence import EvidenceStore\nfrom core.context import Target\n", 1)
    block = '''

class TestTarget(unittest.TestCase):
    def test_root_is_string(self):
        t = Target("https://example.com/a/b?x=1")
        self.assertIsInstance(t.root, str)
        self.assertEqual(t.root, "https://example.com/")

    def test_root_keeps_port(self):
        self.assertEqual(Target("http://h:8080/a").root, "http://h:8080/")

    def test_https_url_upgrades_scheme(self):
        self.assertEqual(Target("http://example.com/a").https_url, "https://example.com/a")

    def test_https_url_drops_default_port(self):
        self.assertEqual(Target("http://example.com:80/a").https_url, "https://example.com/a")

'''
    s = s.replace('\nif __name__ == "__main__":', block + '\nif __name__ == "__main__":', 1)
    p.write_text(s)
    print("  ok   regression tests added")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 5. compile ==="
if python -m compileall -q core modules ui main.py config.py 2>&1 | tail -8; then
  ok "compile clean"
else
  bad "compile errors"; FAILED=$((FAILED+1))
fi

echo "=== 6. selftest ==="
python tests/selftest.py || { bad "selftest"; FAILED=$((FAILED+1)); }

echo "=== 7. full unit tests ==="
python -m unittest discover tests -v 2>&1 | grep -Ev '^\s*$' | tail -70
RC=${PIPESTATUS[0]}
[ "$RC" -ne 0 ] && { bad "unit tests"; FAILED=$((FAILED+1)); }

echo
if [ "$FAILED" -eq 0 ]; then
  printf '%sAll green.%s\n' "$G" "$N"
else
  printf '%s%d issue(s) remain - paste full output.%s\n' "$R" "$FAILED" "$N"; exit 1
fi
