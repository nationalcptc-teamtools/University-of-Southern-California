#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/run/.env" 2>/dev/null || true
bash "$ROOT/bin/nmap_safe.sh"
bash "$ROOT/bin/http_passive.sh"
bash "$ROOT/bin/smb_safe.sh"
bash "$ROOT/bin/ldap_kerb_safe.sh"
bash "$ROOT/bin/ftp_ssh_banner.sh"
[[ -x "$ROOT/bin/logger.py" ]] && python3 "$ROOT/bin/logger.py" --event recon --target all --note "recon_safe complete"
echo "[+] recon_safe complete"
