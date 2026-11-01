#!/usr/bin/env bash
# Install / status external tools. Nothing here is required.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'

reg() { python -c "
import yaml,sys
for t in yaml.safe_load(open('config/tools.yaml')):
    print(t['id'], t['bin'], t['install'], t['pkg'])
"; }

if [ "${1:-}" = "-s" ]; then
  printf '%-14s %-10s %s\n' TOOL STATE NOTE
  reg | while read -r id bin how pkg; do
    if command -v "$bin" >/dev/null 2>&1; then printf '%-14s %sready%s\n' "$id" "$G" "$N"
    else printf '%-14s %smissing%s  (%s)\n' "$id" "$Y" "$N" "$how $pkg"; fi
  done
  exit 0
fi

echo "=== installing external tools ==="
echo "Go tools compile locally and take 200-400 MB of module cache."
echo
command -v go >/dev/null 2>&1 || pkg install -y golang || echo "go install failed"
command -v pip >/dev/null 2>&1 || python -m ensurepip >/dev/null 2>&1

reg | while read -r id bin how pkg; do
  command -v "$bin" >/dev/null 2>&1 && { printf '  %s already present\n' "$id"; continue; }
  printf '  %s ... ' "$id"
  case "$how" in
    go)  go install -b "$PREFIX/bin" "$pkg" >/dev/null 2>&1 ;;
    pip) python -m pip install --no-cache-dir "$pkg" >/dev/null 2>&1 ;;
  esac
  command -v "$bin" >/dev/null 2>&1 && printf '%sok%s\n' "$G" "$N" || printf '%sfailed%s\n' "$Y" "$N"
done

echo
echo "Status:"; bash tools.sh -s
echo
echo "Missing tools are skipped automatically - TSMSS never depends on them."
