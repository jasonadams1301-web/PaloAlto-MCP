#!/bin/bash
# Install paloalto-mcp on the Ubuntu server (run from the project folder).
#   bash install.sh
# Code lives in /opt/paloalto-mcp (root-owned, so the agent cannot change it); config in /etc/paloalto-mcp.
# Passwords/keys are NOT written by this script; store them with set-secret.sh (see the end).
set -euo pipefail
cd "$(dirname "$0")"

id paloalto-mcp >/dev/null 2>&1 || sudo useradd --system --home-dir /opt/paloalto-mcp --shell /usr/sbin/nologin paloalto-mcp
sudo install -d -o root -g root -m 755 /opt/paloalto-mcp
sudo install -d -o root -g paloalto-mcp -m 750 /etc/paloalto-mcp
sudo install -d -o root -g paloalto-mcp -m 750 /etc/paloalto-mcp/certs
sudo install -d -o paloalto-mcp -g paloalto-mcp -m 750 /var/log/paloalto-mcp
sudo install -d -o root -g root -m 700 /etc/paloalto-mcp/credentials
sudo python3 -m venv /opt/paloalto-mcp/venv
sudo /opt/paloalto-mcp/venv/bin/pip install -q -r requirements.txt
sudo rm -rf /opt/paloalto-mcp/app
sudo cp -r app /opt/paloalto-mcp/
sudo install -o root -g root -m 755 scan-cert.py /opt/paloalto-mcp/scan-cert.py
sudo install -o root -g root -m 755 import-panorama.py /opt/paloalto-mcp/import-panorama.py
sudo chown -R root:root /opt/paloalto-mcp/app

sudo test -f /etc/paloalto-mcp/paloalto-mcp.env || sudo install -o root -g paloalto-mcp -m 640 paloalto-mcp.env.example /etc/paloalto-mcp/paloalto-mcp.env
sudo test -f /etc/paloalto-mcp/inventory.yaml || sudo install -o root -g paloalto-mcp -m 640 inventory.example.yaml /etc/paloalto-mcp/inventory.yaml
sudo install -o root -g root -m 644 paloalto-mcp.service /etc/systemd/system/paloalto-mcp.service
sudo systemctl daemon-reload
bash "$(dirname "$0")/sync-credentials.sh"

echo "1. Edit /etc/paloalto-mcp/inventory.yaml (Panorama and firewalls)"
echo "2. Store the read-only login (prompts without echo):  bash set-secret.sh panos_user_firewall ; bash set-secret.sh panos_pass_firewall   (or *_panorama)"
echo "3. Pin each device certificate after checking its fingerprint:  /opt/paloalto-mcp/venv/bin/python /opt/paloalto-mcp/scan-cert.py <host>"
echo "4. Start:  sudo systemctl enable --now paloalto-mcp && sudo ss -lntp | grep ':8766'   # must show 127.0.0.1"
