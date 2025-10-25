#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT_DIR/run/.env" 2>/dev/null || true
OUT_SUB="${OUT_DIR:-$ROOT_DIR/out}/banners/$(date -u +%Y%m%d_%H%M%SZ)"
mkdir -p "$OUT_SUB"
TARGETS=()
if compgen -G "$ROOT_DIR/out/nmap/*.gnmap" >/dev/null 2>&1; then
  while read -r ip; do TARGETS+=("$ip"); done < <(grep -hE " (21|22)/open" "$ROOT_DIR"/out/nmap/*.gnmap | awk '{print $2}' | sort -u)
fi
for h in "${TARGETS[@]}"; do
  safe=$(echo "$h" | tr '/:' '_' ); out="$OUT_SUB/${safe}.txt"
  {
    echo "## SSH banner"; timeout 5 bash -c "echo | nc -nv $h 22" 2>&1 || true
    echo -e "\n## FTP banner"; timeout 5 bash -c "echo | nc -nv $h 21" 2>&1 || true
    echo -e "\n## FTP anonymous (single attempt)"; timeout 8 bash -lc "printf 'USER anonymous\r\nPASS test@test\r\nQUIT\r\n' | nc -nv $h 21" 2>&1 || true
  } > "$out"
  echo "[+] $out"
done
[[ -x "$ROOT_DIR/bin/logger.py" ]] && python3 "$ROOT_DIR/bin/logger.py" --event recon --target banner --note "ftp/ssh -> $OUT_SUB"
