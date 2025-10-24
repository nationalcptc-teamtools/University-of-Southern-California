#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT_DIR/run/.env" 2>/dev/null || true
OUT_SUB="${OUT_DIR:-$ROOT_DIR/out}/http/$(date -u +%Y%m%d_%H%M%SZ)"
mkdir -p "$OUT_SUB"
declare -a hosts
if compgen -G "$ROOT_DIR/out/nmap/*.xml" >/dev/null 2>&1; then
  for f in "$ROOT_DIR"/out/nmap/*.xml; do
    xmlstarlet sel -t -m "//host[ports/port[state/@state='open' and (@portid='80' or @portid='443')] ]" \
      -v "address/@addr" -n "$f" 2>/dev/null | while read -r h; do hosts+=("$h"); done
  done
fi
[[ ${#hosts[@]} -eq 0 && -f "$SCOPE_FILE" ]] && mapfile -t hosts < <(awk 'NF && $0!~/^#/' "$SCOPE_FILE")
paths=("/" "/robots.txt" "/sitemap.xml" "/.well-known/security.txt" "/admin" "/backup" "/dev")
for host in "${hosts[@]}"; do
  host=$(echo "$host" | xargs); [[ -z "$host" ]] && continue
  safe=$(echo "$host" | tr '/:' '_' )
  for scheme in http https; do
    url="$scheme://$host"
    out="$OUT_SUB/${safe}_${scheme}.txt"
    {
      echo "### $url"
      echo "## HEADERS"; curl -s -m 8 -D - -o /dev/null "$url" || true
      echo -e "\n## PASSIVE PATHS"
      for p in "${paths[@]}"; do code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$url$p"); printf "%3s %s\n" "$code" "$p"; done
      echo -e "\n## TITLE & JS FILES"
      html=$(curl -s -m 8 "$url" || true)
      echo "Title: $(echo "$html" | sed -n 's:.*<title>\\(.*\\)</title>.*:\1:p' | head -n1)"
      echo "JS refs:"; echo "$html" | grep -Eo '<script[^>]+src="[^"]+"' | sed -E 's/.*src="([^"]+)".*/\\1/' | sort -u | head -n 20
    } > "$out"
    echo "[+] $out"
  done
done
[[ -x "$ROOT_DIR/bin/logger.py" ]] && python3 "$ROOT_DIR/bin/logger.py" --event recon --target http --note "passive -> $OUT_SUB"
