#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. EvidenceStore: dedupe must return the same path ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/evidence.py")
s = p.read_text()
old = '''        self._seen: set[str] = set()'''
new = '''        # digest -> repo-relative path, so repeats return the identical string
        self._seen: dict[str, str] = {}'''
old2 = '''        key = self._key(label, body)
        if key in self._seen:
            return f"evidence/{key}.{kind}"
        self._seen.add(key)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:60]
        path = self.dir / f"{safe}_{key}.{kind}"
        try:
            path.write_text(body, encoding="utf-8", errors="replace")
        except OSError:
            return body[:600]
        return f"evidence/{path.name}"'''
new2 = '''        key = self._key(label, body)
        slot = f"{key}.{kind}"
        if slot in self._seen:
            return self._seen[slot]
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:60]
        path = self.dir / f"{safe}_{key}.{kind}"
        try:
            path.write_text(body, encoding="utf-8", errors="replace")
        except OSError:
            return body[:600]
        self._seen[slot] = f"evidence/{path.name}"
        return self._seen[slot]'''
if "self._seen: dict[str, str]" in s:
    print("  skip evidence (already applied)")
elif old not in s or old2 not in s:
    print("  MISS evidence anchor"); sys.exit(1)
else:
    s = s.replace(old, new, 1).replace(old2, new2, 1)
    p.write_text(s)
    print("  ok   evidence dedupe stable")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 2. FakeHttp: survive a redirect to an unresolvable host ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_modules.py")
s = p.read_text()
old = """                    nxt = str(r.url.join(loc))
                    hops.append(Hop(cur, status, nxt))
                    cur = nxt
                    rr = await self.c.request("GET", nxt)
                    status, hdrs = rr.status_code, dict(rr.headers)
                    r = rr"""
new = """                    nxt = str(r.url.join(loc))
                    hops.append(Hop(cur, status, nxt))
                    cur = nxt
                    try:
                        rr = await self.c.request("GET", nxt)
                    except Exception:
                        # mirror HttpClient._walk_redirects: keep the hop, stop walking
                        break
                    status, hdrs = rr.status_code, dict(rr.headers)
                    r = rr"""
if "mirror HttpClient._walk_redirects" in s:
    print("  skip fake http (already applied)")
elif old not in s:
    print("  MISS fake http anchor"); sys.exit(1)
else:
    p.write_text(s.replace(old, new, 1))
    print("  ok   fake http redirect guard")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. compile ==="
if python -m compileall -q core modules ui main.py config.py 2>&1 | tail -8; then
  ok "compile clean"
else
  bad "compile errors"; FAILED=$((FAILED+1))
fi

echo "=== 4. selftest ==="
python tests/selftest.py || { bad "selftest"; FAILED=$((FAILED+1)); }

echo "=== 5. full unit tests (failures only, then summary) ==="
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
