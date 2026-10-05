"""Network tools: interfaces, counters, drops, routes, route lookup, sessions, VPN and GlobalProtect users."""
from app.adapters.panos import PanosClient
from app.commands import COUNTER_SEVERITIES
from app.tools.common import check_limit, check_text, clip, collect_entries, num
from app.validation import Inventory, ValidationError, validate_ip, validate_vr
from app.xmlutil import as_list, dig


async def get_interfaces(inv: Inventory, client: PanosClient, device: str, name_contains: str | None = None,
                         limit: int = 100) -> dict:
    check_limit(limit)
    check_text(name_contains, "name_contains")
    d = inv.resolve(device)
    obj = await client.op(d, "interfaces")
    ifnet = {str(e.get("name")): e for e in collect_entries(dig(obj, "ifnet")) if isinstance(e, dict)}
    hw = {str(e.get("name")): e for e in collect_entries(dig(obj, "hw")) if isinstance(e, dict)}
    rows = []
    for name in sorted(set(ifnet) | set(hw)):
        n, h = ifnet.get(name, {}), hw.get(name, {})
        rows.append({"name": name, "state": h.get("state"), "speed": h.get("speed") or h.get("st"),
                     "duplex": h.get("duplex"), "mac": h.get("mac"), "zone": n.get("zone"), "ip": n.get("ip"),
                     "virtual_router": n.get("fwd"), "vsys": n.get("vsys"), "vlan_tag": n.get("tag")})
    total = len(rows)
    if name_contains:
        rows = [r for r in rows if name_contains.lower() in r["name"].lower()]
    shown, note = clip(rows, limit)
    down = [r["name"] for r in rows if str(r["state"]).lower() == "down" and r["zone"]]
    out = {"device": d.name, "interfaces_on_device": total, "matched": len(rows), "returned": len(shown),
           "up": sum(1 for r in rows if str(r["state"]).lower() == "up"),
           "down": sum(1 for r in rows if str(r["state"]).lower() == "down"), "interfaces": shown,
           "attention": [f"interface {n} is down but assigned to a zone" for n in down[:10]]}
    if note:
        out["note"] = note
    if not rows and obj:
        out["parse_warnings"] = ["no interfaces recognised in the response"]
        out["details"] = obj
    return out


def _error_counters(entry: dict) -> dict:
    return {k: num(v) for k, v in entry.items()
            if isinstance(k, str) and ("err" in k.lower() or "drop" in k.lower()) and (num(v) or 0) > 0}


async def get_interface_counters(inv: Inventory, client: PanosClient, device: str, name: str | None = None,
                                 only_errors: bool = False, limit: int = 50) -> dict:
    check_limit(limit)
    d = inv.resolve(device)
    if name is not None:
        from app.validation import validate_interface
        validate_interface(name)
    obj = await client.op(d, "counters_interface")
    rows = []
    for section in ("ifnet", "hw"):
        for e in collect_entries(dig(obj, section)):
            if not isinstance(e, dict):
                continue
            if name and str(e.get("name", "")).lower() != name.lower():
                continue
            errs = _error_counters(e)
            if only_errors and not errs:
                continue
            rows.append({"name": e.get("name"), "table": section, "error_or_drop_counters": errs,
                         "counters": e if name else {k: e[k] for k in e if k in ("ibytes", "obytes", "ipackets", "opackets")}})
    shown, note = clip(rows, limit)
    out = {"device": d.name, "matched": len(rows), "returned": len(shown), "interfaces": shown,
           "note": "counters are cumulative since boot or the last clear; 'ifnet' is the logical interface, 'hw' the port"}
    if note:
        out["note_more"] = note
    return out


async def get_drop_counters(inv: Inventory, client: PanosClient, device: str, delta: str = "yes",
                            severity: str = "drop", limit: int = 40) -> dict:
    check_limit(limit)
    d = inv.resolve(device)
    obj = await client.op(d, "counters_global", delta=delta, severity=severity)
    rows = [{"name": e.get("name"), "value": num(e.get("value")), "rate_per_second": num(e.get("rate")),
             "category": e.get("category"), "aspect": e.get("aspect"), "severity": e.get("severity"),
             "description": e.get("desc")}
            for e in collect_entries(dig(obj, "global")) if isinstance(e, dict)]
    rows = [r for r in rows if (r["value"] or 0) > 0]
    rows.sort(key=lambda r: r["value"] or 0, reverse=True)
    shown, note = clip(rows, limit)
    out = {"device": d.name, "delta": delta.lower(), "severity": severity.lower(), "counters_nonzero": len(rows),
           "counters": shown,
           "note": "delta=yes shows what changed since the last reading; use delta=no for totals since boot"}
    if note:
        out["note_more"] = note
    return out


async def get_routes(inv: Inventory, client: PanosClient, device: str, virtual_router: str | None = None,
                     destination_contains: str | None = None, limit: int = 100) -> dict:
    check_limit(limit)
    check_text(destination_contains, "destination_contains")
    if virtual_router is not None:
        validate_vr(virtual_router)
    d = inv.resolve(device)
    obj = await client.op(d, "routes")
    rows = [{"virtual_router": e.get("virtual-router"), "destination": e.get("destination"),
             "next_hop": e.get("nexthop"), "metric": e.get("metric"), "flags": e.get("flags"), "age": e.get("age"),
             "interface": e.get("interface"), "table": e.get("route-table")}
            for e in collect_entries(obj) if isinstance(e, dict) and e.get("destination")]
    total = len(rows)
    if virtual_router:
        rows = [r for r in rows if str(r["virtual_router"]).lower() == virtual_router.lower()]
    if destination_contains:
        rows = [r for r in rows if destination_contains in str(r["destination"])]
    defaults = [r for r in rows if r["destination"] == "0.0.0.0/0"]
    shown, note = clip(rows, limit)
    out = {"device": d.name, "routes_on_device": total, "matched": len(rows), "returned": len(shown), "routes": shown,
           "default_routes": defaults}
    if note:
        out["note"] = note
    if not total and obj:
        out["parse_warnings"] = ["no routes recognised in the response"]
        out["details"] = obj
    return out


async def _lookup_one(client: PanosClient, d, destination: str, vr: str) -> dict:
    obj = await client.op(d, "route_lookup", virtual_router=vr, ip=destination)
    res = obj if isinstance(obj, dict) else {}
    return {"virtual_router": vr, "interface": res.get("interface"), "next_hop": res.get("nh") or res.get("nexthop"),
            "source_address": res.get("src"), "metric": res.get("metric")}


async def lookup_route(inv: Inventory, client: PanosClient, device: str, destination: str,
                       virtual_router: str | None = None) -> dict:
    """The firewall's own forwarding lookup. Without virtual_router, every virtual router that has routes is asked."""
    validate_ip(destination, "destination")
    if virtual_router is not None:
        validate_vr(virtual_router)
    d = inv.resolve(device)
    if virtual_router:
        names = [virtual_router]
    else:
        obj = await client.op(d, "routes")
        names = sorted({str(e.get("virtual-router")) for e in collect_entries(obj)
                        if isinstance(e, dict) and e.get("virtual-router")})[:6] or ["default"]
    results, errors = [], []
    for vr in names:
        try:
            results.append(await _lookup_one(client, d, destination, vr))
        except Exception as e:                                          # one virtual router failing should not hide the rest
            errors.append({"virtual_router": vr, "error": str(e)[:200]})
    out = {"device": d.name, "destination": destination, "results": results,
           "note": "the firewall's own forwarding lookup (test routing fib-lookup), once per virtual router"}
    if errors:
        out["errors"] = errors
    return out


async def get_session_info(inv: Inventory, client: PanosClient, device: str) -> dict:
    d = inv.resolve(device)
    obj = await client.op(d, "session_info")
    s = obj if isinstance(obj, dict) else {}
    active, maximum = num(s.get("num-active")), num(s.get("num-max"))
    util = round(100 * active / maximum, 1) if active is not None and maximum else None
    out = {"device": d.name, "active_sessions": active, "max_sessions": maximum, "utilization_percent": util,
           "tcp": num(s.get("num-tcp")), "udp": num(s.get("num-udp")), "icmp": num(s.get("num-icmp")),
           "packets_per_second": num(s.get("pps")), "connections_per_second": num(s.get("cps")),
           "kbits_per_second": num(s.get("kbps")),
           "attention": [f"session table is {util}% full"] if util is not None and util >= 80 else []}
    if not s:
        out["parse_warnings"] = ["no session information recognised in the response"]
    return out


async def find_sessions(inv: Inventory, client: PanosClient, device: str, source: str | None = None,
                        destination: str | None = None, destination_port: int | None = None,
                        source_port: int | None = None, application: str | None = None, protocol: str | None = None,
                        from_zone: str | None = None, to_zone: str | None = None, rule: str | None = None,
                        state: str | None = None, limit: int = 25) -> dict:
    check_limit(limit)
    filters = {"source": source, "destination": destination, "destination_port": destination_port,
               "source_port": source_port, "application": application, "protocol": protocol,
               "from_zone": from_zone, "to_zone": to_zone, "rule": rule, "state": state}
    given = {k: v for k, v in filters.items() if v is not None}
    if not given:
        raise ValidationError("give at least one filter (source, destination, destination_port, application, ...) "
                              "so the search does not dump the whole session table")
    d = inv.resolve(device)
    obj = await client.op(d, "session_all", **given)
    rows = [e for e in collect_entries(obj) if isinstance(e, dict)]
    shown, note = clip(rows, limit)
    out = {"device": d.name, "filters": given, "sessions_found": len(rows), "returned": len(shown), "sessions": shown}
    if note:
        out["note"] = note
    return out


def _tunnel_attention(rows: list[dict], label: str) -> list[str]:
    bad = []
    for r in rows:
        st = str(r.get("state") or r.get("tunnel-state") or "").lower()
        if st in ("init", "down", "inactive"):
            bad.append(f"{label} {r.get('name') or r.get('gateway') or ''} is {st}".strip())
    return bad[:10]


async def get_vpn_status(inv: Inventory, client: PanosClient, device: str, limit: int = 50) -> dict:
    check_limit(limit)
    d = inv.resolve(device)
    ike = [e for e in collect_entries(await client.op(d, "vpn_ike_sa")) if isinstance(e, dict)]
    ipsec = [e for e in collect_entries(await client.op(d, "vpn_ipsec_sa")) if isinstance(e, dict)]
    ike_shown, _ = clip(ike, limit)
    ipsec_shown, _ = clip(ipsec, limit)
    return {"device": d.name, "ike_gateways_found": len(ike), "ipsec_tunnels_found": len(ipsec),
            "ike_gateways": ike_shown, "ipsec_tunnels": ipsec_shown,
            "attention": _tunnel_attention(ike, "IKE gateway") + _tunnel_attention(ipsec, "IPsec tunnel")}


async def get_globalprotect_users(inv: Inventory, client: PanosClient, device: str, limit: int = 50) -> dict:
    check_limit(limit)
    d = inv.resolve(device)
    rows = [e for e in collect_entries(await client.op(d, "gp_users")) if isinstance(e, dict)]
    shown, note = clip(rows, limit)
    out = {"device": d.name, "users_connected": len(rows), "returned": len(shown), "users": shown,
           "note": "connected GlobalProtect users on this gateway; includes usernames and addresses"}
    if note:
        out["note_more"] = note
    return out
