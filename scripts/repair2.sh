#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
bad(){ printf '%s MISS %s%s\n' "$R" "$N" "$*"; }
FAILED=0

echo "=== 1. show main.py region for inspection ==="
sed -n '145,185p' main.py | cat -A | sed 's/\$$//' | head -45

echo
echo "=== 2. rebuild run_scan tail (index based) ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("main.py")
lines = p.read_text().splitlines(keepends=True)

start = next((i for i, l in enumerate(lines)
              if l.startswith('    status = "interrupted"')), None)
end = next((i for i, l in enumerate(lines)
            if l.startswith('    RUNTIME["active_scan"] = None')), None)
if start is None or end is None or end <= start:
    print(f"  MISS anchors start={start} end={end}")
    sys.exit(1)

tail = '''    status = "interrupted" if stop_event.is_set() else "complete"
    db.finish_scan(scan_id, status)
    db.audit(scan_id, "scan_end", status)
    await tap.wake_lock(False)

    rows = [dict(r) for r in db.findings(scan_id)]
    targets = [dict(t) for t in db.targets(scan_id)]
    from core.finding import Finding
    findings_objs = []
    for r in rows:
        data = {k: v for k, v in r.items() if k in Finding.__dataclass_fields__}
        data["target"] = r["target_url"]
        findings_objs.append(Finding(**data))
    overall, grade = score(findings_objs)

    console.print(Panel(
        f"Scan [bold]{scan_id}[/bold] {status}\\n"
        f"Completed {scheduler.state.completed}  Failed {scheduler.state.failed}  "
        f"Skipped {scheduler.state.skipped}\\n"
        f"Findings: {menu.severity_bar(dict(counters))}\\n"
        f"Score {overall}/100 (grade {grade})  Duration {scheduler.state.elapsed}s",
        border_style="green" if status == "complete" else "yellow"))
    console.print(f"[grey62]Reports: {BASE / 'reports'}[/grey62]")

    if config.get("safety.notify_on_complete", True):
        await tap.notify("TSMSS scan finished",
                         f"{status}: {scheduler.state.completed} done, {len(rows)} findings")
    await tap.vibrate()
    RUNTIME["active_scan"] = None
'''
lines[start:end + 1] = [tail]
p.write_text("".join(lines))
print(f"  ok   replaced lines {start + 1}-{end + 1}")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 3. validator.py: stop truncating at first space ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("core/validator.py")
s = p.read_text()
old = '    s = s.split()[0]\n'
new = ('    if "#" in s:\n'
       '        s = s.split("#", 1)[0].strip()\n'
       '        if not s:\n'
       '            return ""\n')
if new in s:
    print("  skip validator (already applied)")
elif old not in s:
    print("  MISS validator anchor"); sys.exit(1)
else:
    p.write_text(s.replace(old, new, 1))
    print("  ok   validator split fix")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 4. installer.sh bootstrap (index based) ==="
python - <<'PYEOF'
import pathlib, sys
p = pathlib.Path("installer.sh")
lines = p.read_text().splitlines(keepends=True)
i = next((n for n, l in enumerate(lines)
          if l.startswith('hdr "7. Config bootstrap"')), None)
if i is None:
    print("  MISS bootstrap header"); sys.exit(1)
if any('settings.example.yaml missing' in l for l in lines):
    print("  skip installer (already applied)")
else:
    new = '''if [ ! -f config/settings.yaml ]; then
  if cp config/settings.example.yaml config/settings.yaml 2>/dev/null; then
    ok "settings.yaml created"
  else
    warn "settings.example.yaml missing - defaults will be used"
  fi
else
  ok "settings.yaml kept"
fi
'''
    lines[i + 1:i + 3] = [new]
    p.write_text("".join(lines))
    print("  ok   installer bootstrap")
PYEOF
[ $? -ne 0 ] && FAILED=$((FAILED+1))

echo "=== 5. compile ==="
if python -m compileall -q core modules ui main.py config.py 2>&1 | tail -5; then
  ok "compile clean"
else
  bad "compile errors"; FAILED=$((FAILED+1))
fi

echo
if [ "$FAILED" -eq 0 ]; then
  printf '%sCode is now consistent.%s  Run:  bash installer.sh\n' "$G" "$N"
else
  printf '%s%d issue(s) - paste the MISS lines.%s\n' "$R" "$FAILED" "$N"
  exit 1
fi
