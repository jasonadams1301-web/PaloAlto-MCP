"""Log search: structured filters over fixed time windows. No free-text filter language is accepted."""
import collections

from app.adapters.panos import PanosClient
from app.commands import LOG_TYPES, LOG_WINDOWS, build_log_query
from app.tools.common import check_limit
from app.validation import Inventory, ValidationError

# the fields worth showing per log type (the device returns many more)
FIELDS = {
    "traffic": ("time_generated", "src", "dst", "sport", "dport", "proto", "app", "rule", "action", "session_end_reason",
                "srcuser", "dstuser", "from", "to", "bytes", "natsrc", "natdst", "natdport", "repeatcnt"),
    "threat": ("time_generated", "src", "dst", "sport", "dport", "app", "rule", "action", "threatid", "severity",
               "category", "direction", "subtype", "srcuser", "misc"),
    "url": ("time_generated", "src", "dst", "dport", "app", "rule", "action", "category", "misc", "srcuser"),
    "wildfire": ("time_generated", "src", "dst", "app", "rule", "action", "filename", "category", "verdict", "severity"),
    "system": ("time_generated", "eventid", "severity", "module", "subtype", "opaque", "object"),
    "config": ("time_generated", "admin", "host", "cmd", "result", "path"),
    "globalprotect": ("time_generated", "eventid", "srcuser", "public_ip", "machinename", "stage", "status", "opaque"),
    "userid": ("time_generated", "datasourcename", "ip", "user", "factor", "factortype"),
    "auth": ("time_generated", "ip", "user", "authpolicy", "serverprofile", "event", "desc"),
}
FLOW_TYPES = ("traffic", "threat", "url", "wildfire")
APPLICABLE = {                       # which filters make sense for which log types
    "source": FLOW_TYPES + ("globalprotect", "userid", "auth"), "destination": FLOW_TYPES,
    "application": FLOW_TYPES, "action": FLOW_TYPES, "rule": FLOW_TYPES, "destination_port": FLOW_TYPES,
    "from_zone": FLOW_TYPES, "to_zone": FLOW_TYPES, "severity": ("threat", "system", "wildfire"),
}


async def search_logs(inv: Inventory, client: PanosClient, device: str, log_type: str = "traffic", window: str = "1h",
                      source: str | None = None, destination: str | None = None, application: str | None = None,
                      action: str | None = None, rule: str | None = None, destination_port: int | None = None,
                      from_zone: str | None = None, to_zone: str | None = None, severity: str | None = None,
                      limit: int = 50) -> dict:
    check_limit(limit)
    if log_type not in LOG_TYPES:
        raise ValidationError("log_type must be one of " + ", ".join(LOG_TYPES))
    filters = {"source": source, "destination": destination, "application": application, "action": action,
               "rule": rule, "destination_port": destination_port, "from_zone": from_zone, "to_zone": to_zone,
               "severity": severity}
    for name, val in filters.items():
        if val is not None and log_type not in APPLICABLE[name]:
            raise ValidationError(f"{name} does not apply to {log_type} logs")
    query = build_log_query(window, **filters)                              # validates every value
    d = inv.resolve(device)
    entries = await client.log_search(d, log_type, query, limit)
    keep = FIELDS[log_type]
    rows = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        row = {k: e[k] for k in keep if k in e}
        rows.append(row or e)
    out = {"device": d.name, "log_type": log_type, "window": window, "returned": len(rows), "logs": rows,
           "filters": {k: v for k, v in filters.items() if v is not None}}
    if log_type in ("traffic", "threat"):
        out["by_action"] = dict(collections.Counter(str(r.get("action")) for r in rows))
    if len(rows) >= limit:
        out["note"] = "the result was capped at limit; narrow the window or add filters to see other entries"
    out["time_note"] = "times are as logged by the device; windows are relative to the device's clock"
    return out
