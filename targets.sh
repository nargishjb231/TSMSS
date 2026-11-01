#!/usr/bin/env bash
# TSMSS target-list builder. Opens a numbered slot template, then scans.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || exit 1

G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
warn(){ printf '%s warn %s%s\n' "$Y" "$N" "$*"; }
die(){ printf '%sFAIL%s %s\n' "$R" "$N" "$*"; exit 1; }

SLOTS=60; FILE="targets.txt"; APPEND=0; YES=0; RUN=1

while [ $# -gt 0 ]; do
  case "$1" in
    -n) [ $# -ge 2 ] || die "-n needs a number"; SLOTS="$2"; shift 2 ;;
    -f) [ $# -ge 2 ] || die "-f needs a path"; FILE="$2"; shift 2 ;;
    -a) APPEND=1; shift ;;
    -y) YES=1; shift ;;
    -r) RUN=0; shift ;;
    -h|--help)
      cat <<'U'
TSMSS target-list builder

  ./targets.sh            60-slot template, edit, then scan
  ./targets.sh -n 100     100 slots instead of 60
  ./targets.sh -a         append slots to the existing list
  ./targets.sh -f x.txt   use another file
  ./targets.sh -y         skip the confirmation prompt
  ./targets.sh -r         save only, do not scan
  ./targets.sh -h         this help

Replace each "# NN" marker with one authorized URL. Unfilled slots stay
commented out and are ignored, so you can use 3 of 60 and it still works.
U
      exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$SLOTS" in ''|*[!0-9]*) die "-n must be a number" ;; esac
[ "$SLOTS" -ge 1 ] && [ "$SLOTS" -le 500 ] || die "-n must be 1..500"

command -v python >/dev/null 2>&1 || die "python missing - run: bash installer.sh"
python -c "import httpx, dns, bs4, rich, yaml" 2>/dev/null || die "deps missing - run: bash installer.sh"

mkdir -p .run
if [ -s "$FILE" ]; then
  BK=".run/backup-$(basename "$FILE")-$(date +%Y%m%d-%H%M%S)"
  cp "$FILE" "$BK" && warn "previous list backed up to $BK"
fi

make_slots() {
  local i
  for i in $(seq -w 1 "$1"); do printf '# %s \n' "$i"; done
}

if [ "$APPEND" -eq 1 ]; then
  printf '\n' >> "$FILE"
  make_slots "$SLOTS" >> "$FILE"
  ok "appended $SLOTS slot(s) to $FILE"
else
  {
    cat <<'HDR'
# =====================================================================
#  TSMSS TARGET LIST
#  Replace each "# NN" marker with one authorized URL, e.g.
#     https://example.com
#     https://staging.example.com/login
#  Unfilled slots are comments and are ignored. Blank lines are fine.
# =====================================================================
HDR
    make_slots "$SLOTS"
  } > "$FILE"
  ok "template with $SLOTS slots written to $FILE"
fi

if command -v nano >/dev/null 2>&1; then
  echo
  echo "Save with Ctrl-O, Enter, then exit with Ctrl-X."
  nano "$FILE" || true
else
  echo
  echo "No nano. Paste your URLs one per line, blank line to finish."
  : > .run/paste.txt
  while IFS= read -r line; do
    [ -z "$line" ] && break
    printf '%s\n' "$line" >> .run/paste.txt
  done
  cat .run/paste.txt >> "$FILE"
fi

echo
echo "=== validate ==="
COUNT=$(python - "$FILE" <<'PY'
import sys
sys.path.insert(0, ".")
from core.validator import load_targets
urls, rej = load_targets(sys.argv[1])
real = [r for r in rej if not str(r["raw"]).startswith("#")]
for r in real[:10]:
    print(f"  reject line {r['line']}: {r['raw'][:60]} -> {r['reason']}", file=sys.stderr)
print(len(urls))
PY
) || die "validation failed"
COUNT="${COUNT:-0}"

if [ "$COUNT" -eq 0 ]; then
  warn "no valid URLs found - file kept at $FILE"
  echo "  Fill the slots, then run: bash targets.sh -r  (or bash scan.sh)"
  exit 1
fi
ok "$COUNT valid target(s) in $FILE"

[ "$RUN" -eq 1 ] || { echo "saved only - run later with: bash scan.sh -f $FILE"; exit 0; }

if [ "$YES" -eq 0 ]; then
  printf '\nScan %s target(s) now? [y/N] ' "$COUNT"
  read -r ans
  case "$ans" in y|Y|yes|YES) ;; *) echo "saved only"; exit 0 ;; esac
fi

echo
printf '%sCtrl-C stops gracefully and keeps a resume point%s\n\n' "$C" "$N"
python main.py --batch "$FILE" --yes
RC=$?
echo
if [ "$RC" -eq 0 ]; then
  printf '%sdone%s reports in ./reports/html/\n' "$G" "$N"
else
  printf '%sexit %s%s - resume with: python main.py -> 13\n' "$Y" "$RC" "$N"
fi
exit "$RC"
