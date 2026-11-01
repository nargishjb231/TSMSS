#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1

echo "=== 1. local core/evidence.py (relevant lines) ==="
grep -n "_seen\|def save\|write_text\|return f\"evidence\|return body\|mkdir" core/evidence.py

echo
echo "=== 2. minimal repro ==="
python - <<'PYEOF'
import pathlib, sys, tempfile, traceback
sys.path.insert(0, ".")
from core.evidence import EvidenceStore

with tempfile.TemporaryDirectory(dir="tests") as d:
    base = pathlib.Path(d)
    print("tempdir:", d, "exists:", base.exists())
    es = EvidenceStore(base, max_bytes=20)
    print("es.dir:", es.dir, "exists:", es.dir.exists())
    try:
        a = es.save("lbl", "x" * 100)
        print("returned:", repr(a))
        target = base / "evidence" / pathlib.Path(a).name
        print("target:", target)
        print("target exists:", target.exists())
        print("rglob:", [str(x.relative_to(base)) for x in base.rglob("*")])
    except Exception:
        traceback.print_exc()
PYEOF

echo
echo "=== 3. write_text probe on this filesystem ==="
python - <<'PYEOF'
import pathlib, tempfile, traceback
with tempfile.TemporaryDirectory(dir="tests") as d:
    p = pathlib.Path(d) / "sub" / "f.txt"
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("hello", encoding="utf-8", errors="replace")
        print("  ok   write_text works ->", p, p.exists())
    except Exception:
        print("  MISS write_text failed")
        traceback.print_exc()
PYEOF
