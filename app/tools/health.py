"""Health tools: system info, resources, disk, HA, licences, certificates and recent jobs.

PAN-OS response layouts vary a little between versions, so each tool pulls out the fields it understands and also returns
the parsed device response ("details") so nothing the device said is hidden."""
import re
import time
from datetime import datetime, timezone

from app.adapters.panos import PanosClient
from app.tools.common import check_limit, clip, collect_entries, text_of
from app.validation import Inventory
from app.xmlutil import as_list, dig

SOON_DAYS = 60


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


async def get_system_info(inv: Inventory, client: PanosClient, device: str) -> dict:
    d = inv.resolve(device)
    obj = await client.op(d, "system_info")
    s = dig(obj, "system", default=obj if isinstance(obj, dict) else {}) or {}
    g = lambda k: s.get(k) if isinstance(s, dict) else None                        # noqa: E731
    out = {"device": d.name, "hostname": g("hostname"), "model": g("model"), "serial": g("serial"),
           "sw_version": g("sw-version"), "uptime": g("uptime"), "ip_address": g("ip-address"),
           "app_version": g("app-version"), "threat_version": g("threat-version"), "av_version": g("av-version"),
           "wildfire_version": g("wildfire-version"), "url_filtering_version": g("url-filtering-version"),
           "multi_vsys": g("multi-vsys"), "operational_mode": g("operational-mode"), "details": s}
    if not s:
        out["parse_warnings"] = ["no system information recognised in the response"]
    return out


_CPU = re.compile(r"Cpu\(s\):.*?([0-9.]+)\s*id", re.I)
_MEM = re.compile(r"(Mem)\s*:\s*([0-9.]+)\s*total,\s*([0-9.]+)\s*free,\s*([0-9.]+)\s*used", re.I)
_LOAD = re.compile(r"load average:\s*([0-9.]+),\s*([0-9.]+),\s*([0-9.]+)")


async def get_resources(inv: Inventory, client: PanosClient, device: str) -> dict:
    d = inv.resolve(device)
    text = text_of(await client.op(d, "system_resources"))
    lines = text.splitlines()
    out = {"device": d.name, "output": "\n".join(lines[:25])}
    if m := _LOAD.search(text):
        out["load_average"] = [float(x) for x in m.groups()]
    if m := _CPU.search(text):
        out["management_cpu_used_percent"] = round(100 - float(m.group(1)), 1)
    if m := _MEM.search(text):
        total, used = float(m.group(2)), float(m.group(4))      # 'used' excludes buffers/cache
        out["management_memory_used_percent"] = round(100 * used / total, 1) if total else None
    out["note"] = "management-plane resources; the first 25 lines of the device's own 'show system resources'"
    return out


async def get_disk_space(inv: Inventory, client: PanosClient, device: str) -> dict:
    d = inv.resolve(device)
    text = text_of(await client.op(d, "disk_space"))
    full = [ln for ln in text.splitlines() if re.search(r"\s(9\d|100)%\s", ln + " ")]
    return {"device": d.name, "output": text, "nearly_full": full,
            "attention": [f"filesystem nearly full: {ln.split()[0]}" for ln in full if ln.split()]}


async def get_ha_status(inv: Inventory, client: PanosClient, device: str) -> dict:
    d = inv.resolve(device)
    obj = await client.op(d, "ha_state")
    enabled = dig(obj, "enabled")
    grp = dig(obj, "group", default={}) or {}
    local, peer = dig(grp, "local-info", default={}) or {}, dig(grp, "peer-info", default={}) or {}
    out = {"device": d.name, "ha_enabled": str(enabled).lower() == "yes" if enabled is not None else None,
           "mode": dig(grp, "mode"), "local_state": dig(local, "state"), "peer_state": dig(peer, "state"),
           "running_sync": dig(grp, "running-sync"), "preemptive": dig(local, "preemptive"),
           "peer_connection": dig(peer, "conn-status") or dig(peer, "conn-ha1", "conn-status"),
           "details": obj, "attention": []}
    if out["ha_enabled"]:
        if out["running_sync"] and str(out["running_sync"]).lower() != "synchronized":
            out["attention"].append(f"configuration is {out['running_sync']}, not synchronized")
        for label, st in (("local", out["local_state"]), ("peer", out["peer_state"])):
            if st and str(st).lower() in ("suspended", "non-functional", "tentative", "unknown"):
                out["attention"].append(f"{label} unit is {st}")
        if str(out["peer_connection"] or "up").lower() == "down":
            out["attention"].append("peer connection is down")
    elif out["ha_enabled"] is None:
        out["parse_warnings"] = ["no HA information recognised in the response"]
    return out


def _parse_date(text):
    for fmt in ("%B %d, %Y", "%b %d %H:%M:%S %Y %Z", "%Y/%m/%d"):
        try:
            return datetime.strptime(str(text).strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


async def get_licenses(inv: Inventory, client: PanosClient, device: str) -> dict:
    d = inv.resolve(device)
    obj = await client.op(d, "licenses")
    entries = [e for e in collect_entries(obj) if isinstance(e, dict)]
    now = datetime.now(timezone.utc)
    rows, attention = [], []
    for e in entries:
        exp = e.get("expires")
        when = _parse_date(exp)
        days = (when - now).days if when else None
        expired = str(e.get("expired", "")).lower() == "yes" or (days is not None and days < 0)
        rows.append({"feature": e.get("feature"), "expires": exp, "days_left": days, "expired": expired,
                     "issued": e.get("issued"), "description": e.get("description")})
        if expired:
            attention.append(f"{e.get('feature')} licence has expired")
        elif days is not None and days <= SOON_DAYS:
            attention.append(f"{e.get('feature')} licence expires in {days} days")
    out = {"device": d.name, "licenses": rows, "attention": attention}
    if not rows:
        out["parse_warnings"] = ["no licences recognised in the response"]
        out["details"] = obj
    return out


async def get_certificates(inv: Inventory, client: PanosClient, device: str) -> dict:
    d = inv.resolve(device)
    obj = await client.config_get(d, "certificates")
    entries = [e for e in collect_entries(obj) if isinstance(e, dict)]
    now = time.time()
    rows = []
    for e in entries:
        epoch = _int(e.get("expiry-epoch"))
        when = (datetime.fromtimestamp(epoch, timezone.utc) if epoch else _parse_date(e.get("not-valid-after")))
        days = int((when.timestamp() - now) // 86400) if when else None
        rows.append({"name": e.get("name"), "common_name": e.get("common-name"), "ca": e.get("ca"),
                     "algorithm": e.get("algorithm"), "not_valid_after": e.get("not-valid-after"), "days_left": days})
    rows.sort(key=lambda r: (r["days_left"] is None, r["days_left"] if r["days_left"] is not None else 0))
    attention = [f"certificate {r['name']} " + ("has expired" if r["days_left"] < 0 else f"expires in {r['days_left']} days")
                 for r in rows if r["days_left"] is not None and r["days_left"] <= SOON_DAYS]
    return {"device": d.name, "certificates": rows, "attention": attention,
            "note": "shared certificates from the configuration; certificates inside a vsys are not included"}


async def get_jobs(inv: Inventory, client: PanosClient, device: str, limit: int = 20) -> dict:
    check_limit(limit)
    d = inv.resolve(device)
    obj = await client.op(d, "jobs")
    jobs = [j for j in as_list(dig(obj, "job")) if isinstance(j, dict)]
    jobs.sort(key=lambda j: _int(j.get("id")) or 0, reverse=True)
    rows = [{"id": j.get("id"), "type": j.get("type"), "status": j.get("status"), "result": j.get("result"),
             "user": j.get("user"), "started": j.get("tdeq") or j.get("tenq"), "finished": j.get("tfin"),
             "details": j.get("details")} for j in jobs]
    shown, note = clip(rows, limit)
    failed = [r for r in rows if str(r["result"]).upper() == "FAIL"]
    out = {"device": d.name, "jobs_on_device": len(rows), "returned": len(shown), "jobs": shown,
           "failed_jobs": len(failed), "attention": [f"job {r['id']} ({r['type']}) failed" for r in failed[:5]]}
    if note:
        out["note"] = note
    return out
