#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT_DIR/run/.env" 2>/dev/null || true
OUT_SUB="${OUT_DIR:-$ROOT_DIR/out}/smb/$(date -u +%Y%m%d_%H%M%SZ)"
mkdir -p "$OUT_SUB"
SMB_HOSTS=()
if compgen -G "$ROOT_DIR/out/nmap/*.gnmap" >/dev/null 2>&1; then
  while read -r line; do SMB_HOSTS+=("$(echo "$line" | awk '{print $2}')"); done < <(grep -h "445/open" "$ROOT_DIR"/out/nmap/*.gnmap 2>/dev/null)
fi
[[ ${#SMB_HOSTS[@]} -eq 0 && -f "$SCOPE_FILE" ]] && mapfile -t SMB_HOSTS < <(awk 'NF&&$0!~/^#/' "$SCOPE_FILE")
for h in "${SMB_HOSTS[@]}"; do
  safe=$(echo "$h" | tr '/:' '_' ); out="$OUT_SUB/${safe}.txt"
  {
    echo "# smbclient -L //$h -N"; smbclient -L "//$h" -N 2>&1 || true
    echo -e "\n# rpcclient -U '' $h -c 'enumdomusers'"; rpcclient -U '' "$h" -c 'enumdomusers' 2>&1 || true
  } > "$out"
  echo "[+] $out"
done
[[ -x "$ROOT_DIR/bin/logger.py" ]] && python3 "$ROOT_DIR/bin/logger.py" --event recon --target smb --note "safe -> $OUT_SUB"
