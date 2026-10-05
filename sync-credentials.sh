#!/bin/bash
# Make the service load every stored panos_* credential file. Writes a systemd drop-in listing the files that exist in
# /etc/paloalto-mcp/credentials, so a missing file never stops the service and re-installing the unit never drops one.
# Called by install.sh and set-secret.sh; safe to run any time.
set -euo pipefail
dropin=/etc/systemd/system/paloalto-mcp.service.d
sudo install -d -o root -g root -m 755 "$dropin"
{
  echo "[Service]"
  for f in $(sudo ls /etc/paloalto-mcp/credentials 2>/dev/null | grep -E '^panos_(key|user|pass)_[a-z0-9_]{1,32}$' || true); do
    echo "LoadCredential=$f:/etc/paloalto-mcp/credentials/$f"
  done
} | sudo tee "$dropin/credentials.conf" >/dev/null
sudo systemctl daemon-reload
echo "credentials loaded by the service: $(sudo grep -c '^LoadCredential=' "$dropin/credentials.conf")"
