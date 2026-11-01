#!/usr/bin/env bash
# TSMSS daily runner. `bash scan.sh` or `./scan.sh`
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || exit 1

G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
ok(){ printf '%s  ok  %s%s\n' "$G" "$N" "$*"; }
die(){ printf '%sFAIL%s %s\n' "$R" "$N" "$*"; exit 1; }

usage(){ sed -n '3,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; cat <<'U'

  ./scan.sh                edit targets.txt, then scan
  ./scan.sh -f list.txt    scan a different file
  ./scan.sh -u URL [URL..] scan ad-hoc URLs
  ./scan.sh -l             list current targets
  ./scan.sh -d             validate only, no requests
  ./scan.sh -y             skip the authorization prompt
  ./scan.sh -h             this help

Targets live in targets.txt, one authorized URL per line.
U
}

FILE=""; YES=0; MODE="run"; ADHOC=()
while [ $# -gt 0 ]; do
  case "$1" in
    -f) [ $# -ge 2 ] || die "-f needs a path"; FILE="$2"; shift 2 ;;
    -u) shift; MODE="adhoc"; while [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; do ADHOC+=("$1"); shift; done ;;
    -l) MODE="list"; shift ;;
    -d) MODE="dry"; shift ;;
    -y) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

trap 'printf "\n%syellow%s stopped\n" "$Y" "$N"' INT

echo "=== preflight ==="
command -v python >/dev/null 2>&1 || die "python missing - run: bash installer.sh"
python -c "import httpx, dns, bs4, rich, yaml" 2>/dev/null \
  || die "python deps missing - run: bash installer.sh"
ok "dependencies importable"
[ -f config/settings.yaml ] || { cp config/settings.example.yaml config/settings.yaml 2>/dev/null; }
[ -d modules ] || die "modules/ missing - wrong directory?"
ok "layout intact"

case "$MODE" in
  adhoc)
    [ ${#ADHOC[@]} -gt 0 ] || die "-u needs at least one URL"
    mkdir -p .run
    SRC=".run/adhoc-$(date +%Y%m%d-%H%M%S).txt"
    printf '%s\n' "${ADHOC[@]}" > "$SRC"
    ok "ad-hoc list: $SRC"
    ;;
  *)
    SRC="${FILE:-targets.txt}"
    if [ "$MODE" = "run" ] && [ -z "$FILE" ]; then
      if command -v nano >/dev/null 2>&1; then
        echo
        echo "Editing $SRC - save with Ctrl-O, Enter, then Ctrl-X."
        nano "$SRC"
      else
        printf 'open %s in your editor, then press Enter: ' "$SRC"; read -r _
      fi
    fi
    ;;
esac

[ -f "$SRC" ] || die "no such target file: $SRC"

echo
echo "=== validate ==="
COUNT=$(python - "$SRC" <<'PY'
import sys
sys.path.insert(0, ".")
from core.validator import load_targets
urls, rej = load_targets(sys.argv[1])
for r in rej[:10]:
    print(f"  reject line {r['line']}: {r['raw'][:60]} -> {r['reason']}", file=sys.stderr)
print(len(urls))
PY
) || die "validation failed"
COUNT="${COUNT:-0}"
[ "$COUNT" -gt 0 ] || die "no valid targets in $SRC"
ok "$COUNT valid target(s)"

if [ "$MODE" = "list" ]; then
  python main.py --list "$SRC"
  exit 0
fi
if [ "$MODE" = "dry" ]; then
  echo "dry run only - nothing sent"
  exit 0
fi

LIMIT=$(python -c "import sys;sys.path.insert(0,'.');import config;print(config.load().get('scope.max_targets',500))")
if [ "$COUNT" -gt "$LIMIT" ]; then
  printf '%swarn%s %s targets exceeds limit %s - trimming\n' "$Y" "$N" "$COUNT" "$LIMIT"
fi

if [ "$YES" -eq 0 ]; then
  printf '\nScan %s target(s) now? [y/N] ' "$COUNT"
  read -r ans
  case "$ans" in y|Y|yes|YES) ;; *) echo "aborted"; exit 1 ;; esac
fi

echo
printf '%sStarting batch audit - Ctrl-C stops gracefully and keeps a resume point%s\n' "$C" "$N"
echo
python main.py --batch "$SRC" --yes
RC=$?

echo
if [ "$RC" -eq 0 ]; then
  printf '%sdone%s reports in ./reports/html/\n' "$G" "$N"
else
  printf '%sexit %s%s - resume with: python main.py -> 13\n' "$Y" "$RC" "$N"
fi
exit "$RC"
