#!/bin/bash
# Store one API key as a root-only systemd credential file, without echoing it or putting it in shell history.
#   bash set-secret.sh panos_user_firewall | panos_pass_firewall      (read-only account used for direct firewalls)
#   bash set-secret.sh panos_user_panorama | panos_pass_panorama      (read-only account used for Panorama)
#   an API key can be stored instead: panos_key_<name>.  <name> may also be an inventory `credential:` value.
set -euo pipefail
name="${1:-}"
if ! [[ "$name" =~ ^panos_(key|user|pass)_[a-z0-9_]{1,32}$ ]]; then
  echo "usage: bash set-secret.sh <panos_user_NAME|panos_pass_NAME|panos_key_NAME>  (NAME: firewall, panorama or a credential name)" >&2
  exit 1
fi
read -rsp "$name: " value; echo
[ -n "$value" ] || { echo "empty value, nothing written" >&2; exit 1; }
printf %s "$value" | sudo install -o root -g root -m 600 /dev/stdin "/etc/paloalto-mcp/credentials/$name"
echo "stored /etc/paloalto-mcp/credentials/$name"
echo "named keys also need a LoadCredential= line in the service unit; then: sudo systemctl restart paloalto-mcp"
