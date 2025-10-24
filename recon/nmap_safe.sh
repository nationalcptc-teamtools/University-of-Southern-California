#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT_DIR/run/.env" 2>/dev/null || true
OUT_SUB="${OUT_DIR:-$ROOT_DIR/out}/nmap/$(date -u +%Y%m%d_%H%M%SZ)"
mkdir -p "$OUT_SUB"
TMP=$(mktemp)
[[ -f "$SCOPE_FILE" ]]  && awk 'NF && $0!~/^#/' "$SCOPE_FILE" >>"$TMP"
[[ -f "$TARGETS_CSV" ]] && awk -F, 'NR>1&&NF>=2{print $2}' "$TARGETS_CSV" >>"$TMP"
sort -u "$TMP" -o "$TMP"
while read -r tgt; do
  [[ -z "$tgt" ]] && continue
  safe=$(echo "$tgt" | tr '/:' '_' )
  echo "[*] nmap quick: $tgt"
  nmap -Pn -sS -T3 --top-ports 1000 -sV -sC -oA "$OUT_SUB/${safe}_quick" "$tgt" || true
done < "$TMP"
rm -f "$TMP"
[[ -x "$ROOT_DIR/bin/logger.py" ]] && python3 "$ROOT_DIR/bin/logger.py" --event recon --target nmap --note "safe -> $OUT_SUB"
echo "[+] nmap_safe -> $OUT_SUB"
