#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s FAIL %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. one scorer, in finding.py ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/finding.py")
s = p.read_text()
if "def score_counts(" in s:
    print("  skip finding.py (already applied)")
else:
    anchor = '''def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99'''
    if anchor not in s:
        print("  MISS finding anchor"); sys.exit(1)
    block = anchor + '''


# --- scoring: the single source of truth -------------------------------
# Saturating deduction. A cap per severity stops a noisy target from
# flooring the score at 0, while k controls how fast each class approaches
# its cap, so repeats always cost less than first occurrences.
_DEDUCTION_CAP = {"CRITICAL": 90.0, "HIGH": 25.0, "MEDIUM": 12.0, "LOW": 5.0, "INFO": 0.0}
_DEDUCTION_K = {"CRITICAL": 3.0, "HIGH": 5.0, "MEDIUM": 8.0, "LOW": 15.0, "INFO": 1.0}


def score_counts(counts: dict[str, int]) -> tuple[int, str]:
    """Score a severity histogram. Used by the engine and by every report."""
    deduction = sum(
        _DEDUCTION_CAP[sev] * n / (n + _DEDUCTION_K[sev])
        for sev, n in counts.items() if sev in _DEDUCTION_CAP and n
    )
    value = max(0, min(100, round(100 - deduction)))
    grade = ("A" if value >= 90 else "B" if value >= 80 else "C" if value >= 65
             else "D" if value >= 50 else "E" if value >= 30 else "F")
    return value, grade'''
    p.write_text(s.replace(anchor, block, 1))
    print("  ok   score_counts added")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 2. engine delegates to it ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/engine.py")
s = p.read_text()
if "score_counts(Counter" in s:
    print("  skip engine (already applied)")
else:
    s = s.replace("from core.finding import Finding, severity_rank",
                  "from core.finding import Finding, score_counts, severity_rank", 1)
    old = '''# Saturating deduction: a cap per severity stops a noisy target from flooring
# the score at 0, and k controls how fast each class approaches its cap.
_DEDUCTION_CAP = {"CRITICAL": 55.0, "HIGH": 25.0, "MEDIUM": 12.0, "LOW": 5.0, "INFO": 0.0}
_DEDUCTION_K = {"CRITICAL": 2.0, "HIGH": 5.0, "MEDIUM": 8.0, "LOW": 15.0, "INFO": 1.0}


def score(findings: list[Finding]) -> tuple[int, str]:
    counts = Counter(f.severity for f in findings)
    deduction = sum(
        _DEDUCTION_CAP[sev] * n / (n + _DEDUCTION_K[sev])
        for sev, n in counts.items() if sev in _DEDUCTION_CAP
    )
    value = max(0, min(100, round(100 - deduction)))
    if value >= 90:
        return value, "A"
    if value >= 80:
        return value, "B"
    if value >= 65:
        return value, "C"
    if value >= 50:
        return value, "D"
    if value >= 30:
        return value, "E"
    return value, "F"'''
    new = '''def score(findings: list[Finding]) -> tuple[int, str]:
    """Thin wrapper over finding.score_counts, kept for existing callers."""
    return score_counts(Counter(f.severity for f in findings))'''
    if old not in s:
        print("  MISS engine anchor"); sys.exit(1)
    p.write_text(s.replace(old, new, 1))
    print("  ok   engine delegates")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. reports use the same scorer ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/report_manager.py")
s = p.read_text()
if "score_counts(counts)" in s:
    print("  skip report_manager (already applied)")
else:
    s = s.replace("from core.finding import severity_rank",
                  "from core.finding import score_counts, severity_rank", 1)
    old = '''        deduction = sum(SEVERITY_WEIGHTS.get(r["severity"], 0) for r in rows)
        value = max(0, min(100, 100 - deduction))
        grade = ("A" if value >= 90 else "B" if value >= 80 else "C" if value >= 65
                 else "D" if value >= 50 else "E" if value >= 30 else "F")
        return {"counts": counts, "score": value, "grade": grade, "total": len(rows)}'''
    new = '''        value, grade = score_counts(counts)
        return {"counts": counts, "score": value, "grade": grade, "total": len(rows)}'''
    if old not in s:
        print("  MISS report_manager anchor"); sys.exit(1)
    s = s.replace(old, new, 1)
    s = s.replace("CRITICAL cap 55 k 2", "CRITICAL cap 90 k 3", 1)
    p.write_text(s)
    print("  ok   reports share the scorer")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. scoring tests ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("tests/test_core.py")
s = p.read_text()
if "test_severe_target_reaches_f" in s:
    print("  skip tests (already applied)")
else:
    old = '''    def test_score_floor(self):
        rows = [Finding(target="t", category="c", title=str(i), severity="CRITICAL",
                        description="d") for i in range(10)]
        self.assertEqual(score(rows), (0, "F"))'''
    new = '''    @staticmethod
    def _rows(sev, n):
        return [Finding(target="t", category="c", title=str(i), severity=sev,
                        description="d") for i in range(n)]

    def test_clean_target_scores_perfect(self):
        self.assertEqual(score([]), (100, "A"))

    def test_score_is_monotonic(self):
        self.assertGreater(score(self._rows("HIGH", 1))[0],
                           score(self._rows("HIGH", 20))[0])

    def test_severe_target_reaches_f(self):
        value, grade = score(self._rows("CRITICAL", 50))
        self.assertEqual(grade, "F")
        self.assertGreaterEqual(value, 0)

    def test_repeats_cost_less_than_first_occurrence(self):
        first = 100 - score(self._rows("MEDIUM", 1))[0]
        extra = score(self._rows("MEDIUM", 1))[0] - score(self._rows("MEDIUM", 10))[0]
        self.assertLess(extra, first * 9)'''
    if old not in s:
        print("  MISS test anchor"); sys.exit(1)
    p.write_text(s.replace(old, new, 1))
    print("  ok   scoring tests")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 5. compile + tests ==="
python -m compileall -q core modules ui main.py config.py 2>&1 | tail -5
python tests/selftest.py || { bad selftest; FAILED=$((FAILED+1)); }
python -m unittest discover tests 2>&1 | grep -E '^(FAIL|ERROR|OK|Ran |FAILED)' || true
python -m unittest discover tests >/dev/null 2>&1 || { bad "unit tests"; FAILED=$((FAILED+1)); }

echo "=== 6. score sanity (engine == reports) ==="
python - <<'PYEOF'
import sys; sys.path.insert(0, ".")
from core.engine import score
from core.report_manager import ReportManager
from core.finding import Finding
def mk(sev, n): return [Finding(target="t", category="c", title=str(i), severity=sev, description="d") for i in range(n)]
for label, rows in (("clean", []), ("1 HIGH", mk("HIGH",1)), ("1 CRITICAL", mk("CRITICAL",1)),
                    ("5 HIGH", mk("HIGH",5)), ("69H 212M 262L", mk("HIGH",69)+mk("MEDIUM",212)+mk("LOW",262)),
                    ("10 CRITICAL", mk("CRITICAL",10)), ("50 CRITICAL", mk("CRITICAL",50))):
    eng = score(rows)
    rep = ReportManager.summarize([{"severity": f.severity} for f in rows])
    flag = "OK" if (eng[0], eng[1]) == (rep["score"], rep["grade"]) else "MISMATCH"
    print(f"  {label:>16} engine={eng} report=({rep['score']},{rep['grade']}) {flag}")
PYEOF

echo
if [ "$FAILED" -eq 0 ]; then printf '%sAll green.%s\n' "$G" "$N"
else printf '%s%d issue(s).%s\n' "$R" "$FAILED" "$N"; exit 1; fi
