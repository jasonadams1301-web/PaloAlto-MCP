"""Device list (from the inventory) and Panorama's own list of managed firewalls."""
from app.adapters.panos import PanosClient
from app.tools.common import LIMIT_MAX, check_limit, check_text, clip, collect_entries
from app.validation import Inventory, ValidationError
from app.xmlutil import dig


async def list_devices(inv: Inventory, name_contains: str | None = None, site: str | None = None,
                       kind: str | None = None, limit: int = 50) -> dict:
    check_limit(limit)
    check_text(name_contains, "name_contains")
    check_text(site, "site")
    if kind is not None and kind.lower() not in ("panorama", "firewall"):
        raise ValidationError("kind must be panorama or firewall")
    alldev = inv.all()
    rows = alldev
    if name_contains:
        rows = [d for d in rows if name_contains.lower() in d.name.lower()]
    if site:
        rows = [d for d in rows if d.site.lower() == site.lower()]
    if kind:
        rows = [d for d in rows if d.kind == kind.lower()]
    shown, note = clip(rows, limit)
    out = {"total_devices": len(alldev), "matched": len(rows), "returned": len(shown),
           "devices": [{"name": d.name, "kind": d.kind, "site": d.site, "model": d.model or None,
                        "address": d.address or None, "managed_by": d.via, "serial": d.serial} for d in shown]}
    if note:
        out["note"] = note
    if not (name_contains or site or kind):
        sites: dict[str, int] = {}
        for d in alldev:
            sites[d.site or "(none)"] = sites.get(d.site or "(none)", 0) + 1
        out["sites"] = sites
    return out


def _device_row(e: dict) -> dict:
    ha = e.get("ha") if isinstance(e.get("ha"), dict) else {}
    return {"serial": e.get("serial"), "hostname": e.get("hostname"), "ip_address": e.get("ip-address"),
            "model": e.get("model"), "sw_version": e.get("sw-version"), "connected": e.get("connected"),
            "ha_state": ha.get("state") or e.get("ha-state"), "uptime": e.get("uptime"),
            "app_version": e.get("app-version"), "threat_version": e.get("threat-version"),
            "device_group": e.get("device-group"), "template": e.get("template")}


async def list_panorama_devices(inv: Inventory, client: PanosClient, panorama: str, connected_only: bool = True,
                                limit: int = 100) -> dict:
    check_limit(limit)
    d = inv.resolve(panorama, kind="panorama")
    obj = await client.op(d, "panorama_connected" if connected_only else "panorama_all")
    entries = [e for e in collect_entries(dig(obj, "devices") if isinstance(obj, dict) and "devices" in obj else obj)
               if isinstance(e, dict)]
    rows = [_device_row(e) for e in entries]
    shown, note = clip(rows, limit)
    known = {x.serial: x.name for x in inv.all() if x.serial}
    for r in shown:
        r["in_inventory_as"] = known.get(r["serial"])
    out = {"panorama": d.name, "devices_reported": len(rows), "returned": len(shown), "devices": shown,
           "not_in_inventory": sum(1 for r in rows if r["serial"] not in known)}
    if note:
        out["note"] = note
    if not rows and obj:
        out["parse_warnings"] = ["no devices recognised in the response; raw result attached"]
        out["raw"] = obj
    return out
