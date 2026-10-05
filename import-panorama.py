#!/usr/bin/env python3
"""Add the firewalls a Panorama manages to the inventory as DIRECT connections, pinning each device certificate.

Run on the server as root (it needs the stored Panorama login and write access to /etc/paloalto-mcp):

    sudo /opt/paloalto-mcp/venv/bin/python /opt/paloalto-mcp/import-panorama.py <panorama name>

Step 1 (review, writes nothing): lists every firewall Panorama reports, with its management IP, certificate fingerprint,
expiry and whether pinning will work, and prints a review code. Compare fingerprints with the devices (or
Panorama's own certificate view), then:

    sudo ... import-panorama.py <panorama name> --write --confirm <review code>

Step 2 (write): scans again and applies only if every certificate still matches what you reviewed. Restart the service after.
Options: --all (include disconnected firewalls), --only TEXT (only hostnames containing TEXT).

Refreshing pins (no Panorama needed): factory certificates expire, and a pin matches one exact certificate.

    sudo ... import-panorama.py --refresh                 review: which pinned firewalls now present a different certificate
    sudo ... import-panorama.py --refresh --write --confirm <review code>

It lists firewalls whose certificate changed (old and new fingerprint, expiry, common name) and any certificates expiring
within 90 days, and writes only what you reviewed. The old certificate file is kept as <name>.pem.bak-<time>. Restart the
service afterwards.
"""
import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("CREDENTIALS_DIRECTORY", "/etc/paloalto-mcp/credentials")

from app import importer                                   # noqa: E402
from app.adapters.panos import PanosClient                  # noqa: E402
from app.tools.common import collect_entries                # noqa: E402
from app.tools.devices import _device_row                   # noqa: E402
from app.validation import Inventory                        # noqa: E402
from app.xmlutil import dig                                 # noqa: E402


async def refresh(a, inv, cert_dir) -> int:
    devices = [d for d in inv.all() if d.kind == "firewall" and d.address and d.tls == "pinned"
               and (not a.only or a.only.lower() in d.name.lower())]
    probes = await importer.probe_all({d.name: d.address for d in devices})
    status = {}
    for d in devices:
        pem_path = os.path.join(cert_dir, f"{d.name}.pem")
        old = open(pem_path, encoding="utf-8").read() if os.path.isfile(pem_path) else None
        status[d.name] = importer.refresh_status(old, probes[d.name])
    by = lambda state: [(d, status[d.name]) for d in devices if status[d.name]["state"] == state]
    changed, bad, gone, unpinned, same = by("changed"), by("bad"), by("unreachable"), by("unpinned"), by("unchanged")
    print(f"{len(devices)} pinned firewall(s) checked: {len(same)} unchanged, {len(changed)} changed, "
          f"{len(bad) + len(unpinned)} with a problem, {len(gone)} unreachable")
    soon = sorted((st["days_left"], d.name) for d, st in same + changed
                  if st["days_left"] is not None and st["days_left"] <= 90)
    if soon:
        print(f"\nCertificates expiring within 90 days ({len(soon)}):  " + ", ".join(f"{n} ({days} d)" for days, n in soon))
    code = importer.review_code([(d.name, st["new_fingerprint"]) for d, st in changed])
    if changed:
        print(f"\nCertificate CHANGED, can be re-pinned ({len(changed)}):")
        for d, st in changed:
            note = "" if st["common_name"] in (d.serial, d.address) else "   (common name differs from serial and address)"
            print(f"  {d.name:<28} {d.address:<16} CN={st['common_name']}  expires {st['not_after']}{note}")
            print(f"      old {st['old_fingerprint']}\n      new {st['new_fingerprint']}")
    for title, rows in (("NOT refreshed, new certificate unusable", bad), ("NOT refreshed, no pin on file", unpinned),
                        ("Unreachable", gone)):
        if rows:
            print(f"\n{title} ({len(rows)}):")
            for d, st in rows:
                print(f"  {d.name:<28} {d.address:<16} {st.get('reason')}")
    if not a.write:
        print("\nNothing was written." + (f" To re-pin exactly this list:  --refresh --write --confirm {code}" if changed else ""))
        return 0
    if a.confirm != code:
        print(f"\nREFUSED: the review code does not match (expected {code}). Review again.", file=sys.stderr)
        return 2
    if not changed:
        print("\nNothing to refresh.")
        return 0
    backups = importer.apply_refresh(cert_dir, {d.name: probes[d.name]["pem"] for d, _ in changed})
    print(f"\nRe-pinned {len(changed)} firewall(s); {len(backups)} old certificate file(s) kept as .bak-*.")
    print("Restart to load them:  sudo systemctl restart paloalto-mcp")
    return 0


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("panorama", nargs="?", help="inventory name of the Panorama (not needed with --refresh)")
    ap.add_argument("--refresh", action="store_true", help="re-check the pinned certificates of firewalls already in the inventory")
    ap.add_argument("--all", action="store_true", help="include firewalls that are not currently connected")
    ap.add_argument("--only", help="only firewalls whose hostname contains this text")
    ap.add_argument("--write", action="store_true", help="apply (needs --confirm)")
    ap.add_argument("--confirm", help="review code printed by the review step")
    a = ap.parse_args()

    inv_path = os.environ.get("INVENTORY_FILE", "/etc/paloalto-mcp/inventory.yaml")
    cert_dir = os.environ.get("PANOS_CERT_DIR", "/etc/paloalto-mcp/certs")
    inv = Inventory.load(inv_path)
    if a.refresh:
        return await refresh(a, inv, cert_dir)
    if not a.panorama:
        ap.error("give the Panorama's inventory name (or use --refresh)")
    pan = inv.resolve(a.panorama, kind="panorama")
    obj = await PanosClient(inv).op(pan, "panorama_all" if a.all else "panorama_connected")
    rows = [_device_row(e) for e in collect_entries(dig(obj, "devices") if isinstance(obj, dict) and "devices" in obj else obj)
            if isinstance(e, dict)]
    if a.only:
        rows = [r for r in rows if a.only.lower() in str(r.get("hostname") or "").lower()]
    print(f"{pan.name} reports {len(rows)} firewall(s)" + ("" if a.all else " (connected only)"))

    existing = inv.all()
    p = importer.plan(rows, {d.name for d in existing}, {d.serial for d in existing if d.serial},
                      {d.address for d in existing if d.address})
    probes = await importer.probe_all({e["name"]: e["address"] for e in p["add"]})

    good, bad = [], []
    for e in p["add"]:
        r = probes[e["name"]]
        (good if r["ok"] else bad).append((e, r))
    code = importer.review_code([(e["name"], r["fingerprint"]) for e, r in good])

    mismatch = [e["name"] for e, r in good if r.get("common_name") != e["serial"]]
    print(f"\nCan be added and pinned ({len(good)}):")
    for e, r in good:
        print(f"  {e['name']:<28} {e['address']:<16} {e.get('model', ''):<10} {r['subject'] or '-'}")
        print(f"      SHA256 {r['fingerprint']}   expires {r['not_after']}   issuer {r['issuer'] or '-'}")
    if good:
        print(f"\nSanity check: {len(good) - len(mismatch)} of {len(good)} certificates have a common name equal to the serial "
              f"Panorama reports for that firewall." + (" Different: " + ", ".join(mismatch) if mismatch else ""))
    if bad:
        print(f"\nNOT added, certificate or connection problem ({len(bad)}):")
        for e, r in bad:
            print(f"  {e['name']:<28} {e['address']:<16} {r['reason']}")
            if r.get("fingerprint"):
                print(f"      SHA256 {r['fingerprint']}")
    if p["problems"]:
        print(f"\nNOT added, cannot be named or located ({len(p['problems'])}):")
        for x in p["problems"]:
            print(f"  {x['device']}: {x['reason']}")
    if p["skipped"]:
        print(f"\nAlready in the inventory ({len(p['skipped'])}): " + ", ".join(x["device"] for x in p["skipped"]))

    if not a.write:
        print(f"\nNothing was written. To apply exactly this list:  --write --confirm {code}")
        return 0
    if a.confirm != code:
        print(f"\nREFUSED: the review code does not match (expected {code}). The devices or their certificates changed "
              f"since you reviewed them, or the code was mistyped. Review again.", file=sys.stderr)
        return 2
    if not good:
        print("\nNothing to add.")
        return 0
    backup = importer.apply(inv_path, cert_dir, [e for e, _ in good], {e["name"]: r["pem"] for e, r in good})
    print(f"\nAdded and pinned {len(good)} firewall(s). Inventory backup: {backup}")
    print("Restart to load them:  sudo systemctl restart paloalto-mcp")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
