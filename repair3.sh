#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
warn(){ printf '%s warn %s%s\n' "$Y" "$N" "$*"; }
FAILED=0

echo "=== 1. install PyYAML ==="
if python -c "import yaml" 2>/dev/null; then
  ok "yaml already importable"
elif pkg install -y python-pyyaml >/dev/null 2>&1 && python -c "import yaml" 2>/dev/null; then
  ok "python-pyyaml installed via pkg"
else
  warn "pkg route failed, trying pip"
  if python -m pip install --no-cache-dir PyYAML >/dev/null 2>&1 && python -c "import yaml" 2>/dev/null; then
    ok "PyYAML installed via pip"
  else
    warn "pip build failed, installing toolchain then retrying"
    pkg install -y clang make python-dev >/dev/null 2>&1
    if python -m pip install --no-cache-dir PyYAML >/dev/null 2>&1 && python -c "import yaml" 2>/dev/null; then
      ok "PyYAML installed after toolchain"
    else
      bad "PyYAML could not be installed"; FAILED=$((FAILED+1))
    fi
  fi
fi
python -c "import yaml; print('   yaml', yaml.__version__)" 2>/dev/null || true

echo "=== 2. requirements.txt trailing newline ==="
python - <<'PYEOF'
import pathlib
p = pathlib.Path("requirements.txt")
s = p.read_text()
if s.endswith("\n"):
    print("  skip requirements.txt (already terminated)")
else:
    p.write_text(s + "\n")
    print("  ok   trailing newline added")
PYEOF

echo "=== 3. harden read loop (unterminated last line) ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("installer.sh")
s = p.read_text()
old = "while IFS= read -r line; do\n"
new = "while IFS= read -r line || [ -n \"$line\" ]; do\n"
if new in s:
    print("  skip installer loop (already hardened)")
elif old not in s:
    print("  MISS installer loop anchor"); sys.exit(1)
else:
    p.write_text(s.replace(old, new, 1))
    print("  ok   loop hardened")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. confirm every requirement is importable ==="
python - <<'PYEOF'
import importlib, pathlib, sys
MAP = {"httpx": "httpx", "dnspython": "dns", "beautifulsoup4": "bs4",
       "rich": "rich", "PyYAML": "yaml"}
missing = []
for line in pathlib.Path("requirements.txt").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    name = line.split(">")[0].split("<")[0].split("=")[0].strip()
    mod = MAP.get(name, name.replace("-", "_"))
    try:
        importlib.import_module(mod)
        print(f"  ok   {name}")
    except ImportError:
        print(f"  MISS {name} (module '{mod}')")
        missing.append(name)
if missing:
    print("missing:", ", ".join(missing))
    sys.exit(1)
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 5. selftest ==="
if python tests/selftest.py; then ok "selftest passed"
else bad "selftest failed"; FAILED=$((FAILED+1)); fi

echo "=== 6. unit tests ==="
if python -m unittest discover tests -v 2>&1 | tail -25; then
  ok "unit tests finished"
else
  bad "unit tests failed"; FAILED=$((FAILED+1))
fi

echo
if [ "$FAILED" -eq 0 ]; then
  printf '%sAll green.%s  Run:  python main.py\n' "$G" "$N"
else
  printf '%s%d issue(s) remain.%s\n' "$R" "$FAILED" "$N"; exit 1
fi
