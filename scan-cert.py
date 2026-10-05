#!/usr/bin/env python3
"""Fetch a device's HTTPS certificate and print its SHA256 fingerprint.

Used to pin a Panorama/firewall certificate. It only READS the certificate and writes nothing. Compare the
fingerprint with the one shown on the device (Device > Certificate Management), then save the PEM yourself:

    /opt/paloalto-mcp/venv/bin/python scan-cert.py panorama.example.net | sudo tee /etc/paloalto-mcp/certs/pan-primary.pem

The file name must be the inventory name of the device that holds the API endpoint (the Panorama for managed firewalls).
"""
import hashlib
import socket
import ssl
import sys


def main(host: str, port: int = 443) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        der = s.getpeercert(binary_form=True)
    print(ssl.DER_cert_to_PEM_cert(der), end="")
    fp = hashlib.sha256(der).hexdigest().upper()
    print("# SHA256 " + ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)), file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: scan-cert.py <host> [port]")
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) == 3 else 443)
