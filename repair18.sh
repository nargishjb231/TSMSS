#!/data/data/com.termux/files/usr/bin/bash
# repair18.sh - repair17's guard `"import re" not in s` matched the substring
# inside "import report_manager", so `import re` was never added while
# `_HEADER_BLOCK = re.compile(...)` was. AST-based check now, repo-wide.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
F=0
ok(){  printf '  %sok%s %s\n'   "$G" "$N" "$1"; }
bad(){ printf '  %sFAIL%s %s\n' "$R" "$N" "$1"; F=$((F+1)); }

echo "=== 0. context: top of core/report_manager.py ==="
head -n 24 core/report_manager.py | cat -n

echo "=== 1. add missing 'import re' where re. is used ==="
CHANGED=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if python - "$f" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
for n in tree.body:
    if isinstance(n, ast.Import) and any(a.name == "re" for a in n.names):
        sys.exit(0)
    if isinstance(n, ast.ImportFrom) and n.module == "re":
        sys.exit(0)
sys.exit(1)
PY
  then continue; fi
  python - "$f" <<'PY'
import ast, pathlib, sys
p = pathlib.Path(sys.argv[1])
src = p.read_text()
tree = ast.parse(src)
top = tree.body
insert, i = 0, 0
if top and isinstance(top[0], ast.Expr) \
   and isinstance(top[0].value, ast.Constant) \
   and isinstance(top[0].value.value, str):
    insert, i = top[0].end_lineno, 1
while i < len(top) and isinstance(top[i], ast.ImportFrom) and top[i].module == "__future__":
    insert = max(insert, top[i].end_lineno); i += 1
lines = src.splitlines(keepends=True)
lines.insert(insert, "import re\n")
p.write_text("".join(lines))
print("    + import re -> %s (line %d)" % (sys.argv[1], insert + 1))
PY
  CHANGED=$((CHANGED+1))
done < <(grep -rlE '\bre\.(compile|match|search|sub|subn|split|findall|finditer|fullmatch|escape|purge)\b' --include='*.py' . 2>/dev/null | sort)

[ "$CHANGED" -gt 0 ] && ok "$CHANGED file(s) patched" || ok "nothing to patch"

echo "=== 2. residual offenders ==="
LEFT=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  python - "$f" <<'PY' || { echo "    still missing: $f"; LEFT=$((LEFT+1)); }
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
for n in tree.body:
    if isinstance(n, ast.Import) and any(a.name == "re" for a in n.names): sys.exit(0)
    if isinstance(n, ast.ImportFrom) and n.module == "re": sys.exit(0)
sys.exit(1)
PY
done < <(grep -rlE '\bre\.(compile|match|search|sub)\b' --include='*.py' . 2>/dev/null | sort)
[ "$LEFT" -eq 0 ] && ok "no file uses re. without importing it" || bad "$LEFT file(s) still missing"

echo "=== 3. compile everything ==="
if python -m compileall -q core modules ui main.py tests >/dev/null 2>&1; then ok "compiles"; else bad "compile errors"; python -m compileall -q core modules ui main.py tests 2>&1 | head -n 20; fi

echo "=== 4. import the offender ==="
if python -c 'import core.report_manager, core.engine, main' 2>>/tmp/r18.err; then ok "report_manager + engine + main import"
else bad "import error"; sed -n '1,15p' /tmp/r18.err; fi

echo "=== 5. selftest ==="
python tests/selftest.py 2>&1 | tail -n 12
python tests/selftest.py >/dev/null 2>&1 && ok selftest || bad selftest

echo "=== 6. unit tests ==="
python -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -n 8
python -m unittest discover -s tests -p 'test_*.py' >/dev/null 2>&1 && ok "unit tests" || bad "unit tests"

echo
if [ "$F" -eq 0 ]; then printf '%sAll green.%s\n' "$G" "$N"
else printf '%s%d issue(s).%s\n' "$R" "$F" "$N"; exit 1; fi
