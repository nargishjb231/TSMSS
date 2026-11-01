#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. scheduler: explicit success flag ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/scheduler.py")
s = p.read_text()
old = '''                    result = await worker(url)
                    ok = not result[2] if len(result) > 2 else True'''
new = '''                    result = await worker(url)
                    # worker returns an explicit ok flag at index 5; the grade
                    # letter at index 2 is truthy either way, so it cannot be used
                    ok = bool(result[5]) if len(result) > 5 else True'''
if "explicit ok flag" in s:
    print("  skip scheduler (already applied)")
elif old not in s:
    print("  MISS scheduler anchor"); sys.exit(1)
else:
    p.write_text(s.replace(old, new, 1))
    print("  ok   scheduler reads explicit flag")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 2. main.py: worker reports ok, on_done consumes it ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("main.py")
s = p.read_text()

old_w = '''        db.add_findings(scan_id, findings)
        return url, findings, extra, "", requests'''
new_w = '''        db.add_findings(scan_id, findings)
        ok = isinstance(extra, str) and extra in tuple("ABCDEF")
        return url, findings, extra, "", requests, ok'''
old_d = '''    async def on_done(url: str, result: tuple) -> None:
        _, findings, extra, error, requests = result
        # `extra` carries a grade letter on success, an error string on failure
        grade_like = isinstance(extra, str) and extra in tuple("ABCDEF")
        status = "done" if grade_like else "failed"'''
new_d = '''    async def on_done(url: str, result: tuple) -> None:
        _, findings, extra, error, requests, ok = result
        status = "done" if ok else "failed"'''
old_s = '''    status = "interrupted" if stop_event.is_set() else "complete"'''
new_s = '''    if scheduler.state.completed == 0 and scheduler.state.failed > 0:
        console.print("[yellow]every target failed - check network and scope[/yellow]")

    status = "interrupted" if stop_event.is_set() else "complete"'''

for old, new, label in ((old_w, new_w, "worker ok flag"),
                        (old_d, new_d, "on_done consumes flag"),
                        (old_s, new_s, "all-failed warning")):
    if new in s and old not in s:
        print("  skip", label)
    elif old not in s:
        print("  MISS", label); sys.exit(1)
    else:
        s = s.replace(old, new, 1); print("  ok  ", label)
p.write_text(s)
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. engine: saturating score ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/engine.py")
s = p.read_text()
old = '''def score(findings: list[Finding]) -> tuple[int, str]:
    deduction = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    value = max(0, min(100, 100 - deduction))'''
new = '''# Saturating deduction: a cap per severity stops a noisy target from flooring
# the score at 0, and k controls how fast each class approaches its cap.
_DEDUCTION_CAP = {"CRITICAL": 55.0, "HIGH": 25.0, "MEDIUM": 12.0, "LOW": 5.0, "INFO": 0.0}
_DEDUCTION_K = {"CRITICAL": 2.0, "HIGH": 5.0, "MEDIUM": 8.0, "LOW": 15.0, "INFO": 1.0}


def score(findings: list[Finding]) -> tuple[int, str]:
    counts = Counter(f.severity for f in findings)
    deduction = sum(
        _DEDUCTION_CAP[sev] * n / (n + _DEDUCTION_K[sev])
        for sev, n in counts.items() if sev in _DEDUCTION_CAP
    )
    value = max(0, min(100, round(100 - deduction)))'''
if "_DEDUCTION_CAP" in s:
    print("  skip engine (already applied)")
elif old not in s:
    print("  MISS engine anchor"); sys.exit(1)
else:
    s = s.replace(old, new, 1)
    if "from collections import Counter" not in s:
        s = s.replace("import traceback", "import traceback\nfrom collections import Counter", 1)
    p.write_text(s)
    print("  ok   saturating score")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. document the new formula ==="
python - <<'PYEOF'
import pathlib
p = pathlib.Path("core/report_manager.py")
s = p.read_text()
old = '''SCORE_METHOD = """Security score = max(0, 100 - sum(weights)), weights:
CRITICAL 25, HIGH 12, MEDIUM 5, LOW 2, INFO 0. Grades: A>=90, B>=80, C>=65,
D>=50, E>=30, F<30. The score is a relative prioritisation aid, not a
compliance verdict; absence of findings is not proof of security."""'''
new = '''SCORE_METHOD = """Each severity contributes a saturating deduction
cap * n / (n + k): CRITICAL cap 55 k 2, HIGH cap 25 k 5, MEDIUM cap 12 k 8,
LOW cap 5 k 15, INFO 0. Score = max(0, 100 - total). Caps stop a noisy target
from flooring at 0 while repeats still cost less than first occurrences.
Grades: A>=90, B>=80, C>=65, D>=50, E>=30, F<30. A relative prioritisation
aid, not a compliance verdict; absence of findings is not proof of security."""'''
if "saturating deduction" in s:
    print("  skip docs")
else:
    p.write_text(s.replace(old, new, 1)); print("  ok   report methodology")
PYEOF

echo "=== 5. compile + tests ==="
python -m compileall -q core modules ui main.py config.py 2>&1 | tail -5
python tests/selftest.py || { bad selftest; FAILED=$((FAILED+1)); }
python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
python -m unittest discover tests >/dev/null 2>&1 || { bad "unit tests"; FAILED=$((FAILED+1)); }

echo "=== 6. score sanity ==="
python - <<'PYEOF'
import sys; sys.path.insert(0, ".")
from core.engine import score
from core.finding import Finding
def mk(sev, n): return [Finding(target="t", category="c", title=str(i), severity=sev, description="d") for i in range(n)]
for label, rows in (("clean", []), ("1 HIGH", mk("HIGH", 1)), ("1 CRITICAL", mk("CRITICAL", 1)),
                    ("5 HIGH", mk("HIGH", 5)), ("69H 212M 262L", mk("HIGH",69)+mk("MEDIUM",212)+mk("LOW",262)),
                    ("50 CRITICAL", mk("CRITICAL", 50))):
    print(f"  {label:>16} -> {score(rows)}")
PYEOF

echo
if [ "$FAILED" -eq 0 ]; then printf '%sAll green.%s\n' "$G" "$N"
else printf '%s%d issue(s).%s\n' "$R" "$FAILED" "$N"; exit 1; fi
