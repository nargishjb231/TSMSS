#!/data/data/com.termux/files/usr/bin/bash
# TSMSS installer — Termux only. Non-destructive, idempotent.
set -uo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SELF_DIR" || exit 1

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
ok(){ printf '%s[ OK ]%s %s\n' "$G" "$N" "$*"; }
warn(){ printf '%s[WARN]%s %s\n' "$Y" "$N" "$*"; }
err(){ printf '%s[FAIL]%s %s\n' "$R" "$N" "$*"; }
hdr(){ printf '\n%s=== %s ===%s\n' "$C" "$*" "$N"; }

FAILED=0
MIN_FREE_KB=262144   # 256 MB

hdr "1. Platform check"
if [ ! -d /data/data/com.termux/files/usr ]; then
  err "Not Termux. TSMSS requires Termux on Android."; exit 1
fi
ok "Termux detected"
ok "Architecture: $(uname -m)"
case "$(uname -m)" in
  aarch64|arm64) ok "ARM64 confirmed" ;;
  *) warn "Non-ARM64 ($(uname -m)); performance not tuned for this CPU" ;;
esac
[ "$(id -u)" = "0" ] && ok "Running as root (optional, unlocks nmap SYN)" \
                      || ok "Unrooted — connect scans only (expected)"

hdr "2. Python check"
if ! command -v python >/dev/null 2>&1; then
  warn "python missing, installing"; pkg install -y python || { err "python install failed"; exit 1; }
fi
PYV="$(python -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
python -c 'import sys;sys.exit(0 if sys.version_info>=(3,9) else 1)' \
  && ok "Python $PYV" || { err "Python >= 3.9 required (found $PYV)"; exit 1; }

hdr "3. Storage check"
FREE_KB="$(df -Pk "$SELF_DIR" | awk 'NR==2{print $4}')"
[ "${FREE_KB:-0}" -ge "$MIN_FREE_KB" ] && ok "Free: $((FREE_KB/1024)) MB" \
  || { err "Need >= 256 MB free, have $((FREE_KB/1024)) MB"; exit 1; }

hdr "4. System packages"
for p in curl git jq openssl whois dnsutils nmap termux-api python-cryptography; do
  if dpkg -s "$p" >/dev/null 2>&1; then ok "$p present"; continue; fi
  printf '  installing %s ... ' "$p"
  if pkg install -y "$p" >/dev/null 2>&1; then printf '%sdone%s\n' "$G" "$N"
  else printf '%sfailed%s\n' "$Y" "$N"; warn "$p unavailable — module degrades gracefully"; fi
done

hdr "5. Python packages"
declare -A IMPORTS=([beautifulsoup4]=bs4 [PyYAML]=yaml [dnspython]=dns [httpx]=httpx [rich]=rich)
python -m pip install --upgrade pip >/dev/null 2>&1
while IFS= read -r line; do
  [ -z "$line" ] && continue; case "$line" in \#*) continue ;; esac
  pkgname="${line%%[<>=]*}"
  mod="${IMPORTS[$pkgname]:-${pkgname//-/_}}"
  python -c "import $mod" 2>/dev/null && { ok "$pkgname present"; continue; }
  printf '  installing %s ... ' "$pkgname"
  python -m pip install --no-cache-dir "$line" >/dev/null 2>&1 \
    && printf '%sdone%s\n' "$G" "$N" \
    || { printf '%sfailed%s\n' "$Y" "$N"; FAILED=$((FAILED+1)); }
done < requirements.txt

hdr "6. Directories"
for d in config core modules ui templates reports reports/html reports/json \
         reports/txt reports/csv database logs tests tests/fixtures; do
  mkdir -p "$d" && ok "$d"
done

hdr "7. Config bootstrap"
if [ ! -f config/settings.yaml ]; then
  if cp config/settings.example.yaml config/settings.yaml 2>/dev/null; then
    ok "settings.yaml created"
  else
    warn "settings.example.yaml missing — defaults will be used"
  fi
else
  ok "settings.yaml exists (kept)"
fi
[ -f targets.txt ] || { printf '# one authorized URL per line\nhttps://example.com\n' > targets.txt; ok "targets.txt"; }

hdr "8. Termux:API"
if command -v termux-battery-status >/dev/null 2>&1; then
  ok "Termux:API available"
else
  warn "Termux:API missing — install the Termux:API app from F-Droid for battery/notify support"
fi

hdr "9. Self-test"
[ -d modules ] || { err "modules/ missing at repo root"; FAILED=$((FAILED+1)); }
python -m compileall -q core modules ui main.py config.py >/dev/null 2>&1 \
  && ok "All sources compile" || { err "Compile errors"; FAILED=$((FAILED+1)); }
python tests/selftest.py && ok "Self-test passed" || { err "Self-test failed"; FAILED=$((FAILED+1)); }

hdr "RESULT"
if [ "$FAILED" -eq 0 ]; then
  printf '%sInstallation complete.%s  Run:  python main.py\n' "$G" "$N"
  command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock
else
  printf '%sInstallation finished with %d problem(s).%s\n' "$Y" "$FAILED" "$N"; exit 2
fi