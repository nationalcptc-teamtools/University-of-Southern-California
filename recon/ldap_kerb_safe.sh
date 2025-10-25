#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT_DIR/run/.env" 2>/dev/null || true
OUT_SUB="${OUT_DIR:-$ROOT_DIR/out}/ldapkerb/$(date -u +%Y%m%d_%H%M%SZ)"
mkdir -p "$OUT_SUB"
HOSTS=()
if compgen -G "$ROOT_DIR/out/nmap/*.gnmap" >/dev/null 2>&1; then
  while read -r ip; do HOSTS+=("$ip"); done < <(grep -hE " (389|88)/open" "$ROOT_DIR"/out/nmap/*.gnmap | awk '{print $2}' | sort -u)
fi
[[ ${#HOSTS[@]} -eq 0 ]] && { echo "No LDAP/Kerberos hosts detected"; exit 0; }
for h in "${HOSTS[@]}"; do
  safe=$(echo "$h" | tr '/:' '_' ); out="$OUT_SUB/${safe}.txt"
  {
    echo "## Nmap ldap* scripts (389)"; nmap -Pn -p389 --script ldap* "$h" 2>/dev/null || true
    echo -e "\n## ldapsearch base DSE"; ldapsearch -x -H "ldap://$h" -s base -b "" 2>/dev/null || true
    echo -e "\n## Kerberos port check (88)"; nmap -Pn -p88 "$h" 2>/dev/null || true
  } > "$out"
  echo "[+] $out"
done
[[ -x "$ROOT_DIR/bin/logger.py" ]] && python3 "$ROOT_DIR/bin/logger.py" --event recon --target ldap/kerb --note "safe -> $OUT_SUB"
