"""Policy lookup (the firewall's own policy-match tests), rule lists, and reading the configuration."""
from app.adapters.panos import PanosClient
from app.commands import NEEDS_DG, PANORAMA_ONLY, XPATHS
import defusedxml.ElementTree as DET
from xml.etree import ElementTree as ET

from app.redact import redact_obj, redact_tree, redact_xml_text, redaction_enabled
from app.tools.common import check_limit, check_text, clip, collect_entries
from app.validation import (Inventory, ValidationError, validate_dg, validate_ip, validate_port, validate_protocol,
                            validate_vsys)
from app.xmlutil import as_list, dig

MAX_LINES = 4000
DEFAULT_LINES = 300
MAX_VALUE_CHARS = 300          # longer text values (embedded images, certificates) are summarised
MAX_OUTPUT_CHARS = 24000


def _pretty_lines(raw: str, redact: bool) -> tuple[list[str], int]:
    """The exported config is one enormous line. Parse it (safely), optionally redact, and print one element per line."""
    try:
        root = DET.fromstring(raw)
    except Exception:
        lines = [ln if len(ln) <= 400 else ln[:400] + f"... [{len(ln)} chars]" for ln in raw.splitlines()]
        return lines, 0
    count = redact_tree(root) if redact else 0
    for el in root.iter():
        if el.text and len(el.text) > MAX_VALUE_CHARS:
            el.text = f"[{len(el.text)} characters of data omitted]"
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode").splitlines(), count


async def policy_match(inv: Inventory, client: PanosClient, device: str, source: str, destination: str,
                       protocol: str = "tcp", destination_port: int | None = None, from_zone: str | None = None,
                       to_zone: str | None = None, application: str | None = None) -> dict:
    validate_ip(source, "source")
    validate_ip(destination, "destination")
    proto = validate_protocol(protocol)
    if proto in ("6", "17") and destination_port is None:
        raise ValidationError("destination_port is required for tcp and udp")
    d = inv.resolve(device, kind="firewall")
    obj = await client.op(d, "policy_match", source=source, destination=destination, protocol=protocol,
                          destination_port=destination_port, from_zone=from_zone, to_zone=to_zone,
                          application=application)
    rules = [r for r in collect_entries(dig(obj, "rules") if isinstance(obj, dict) and "rules" in obj else obj)
             if isinstance(r, dict)]
    first = rules[0] if rules else None
    return {"device": d.name, "matched": bool(rules), "first_match": first, "all_matches": rules,
            "summary": (f"first match: rule '{first.get('name')}' action {first.get('action')}" if first and
                        first.get("name") else "no explicit rule matched (the default rules apply)"),
            "test": {"source": source, "destination": destination, "protocol": protocol,
                     "destination_port": destination_port, "from_zone": from_zone, "to_zone": to_zone,
                     "application": application},
            "note": "result of the firewall's own security-policy-match test; it evaluates rules in order, first match wins"}


async def nat_match(inv: Inventory, client: PanosClient, device: str, source: str, destination: str,
                    from_zone: str, to_zone: str, protocol: str = "tcp", destination_port: int | None = None,
                    source_port: int | None = None) -> dict:
    validate_ip(source, "source")
    validate_ip(destination, "destination")
    validate_protocol(protocol)
    d = inv.resolve(device, kind="firewall")
    obj = await client.op(d, "nat_match", source=source, destination=destination, from_zone=from_zone, to_zone=to_zone,
                          protocol=protocol, destination_port=destination_port, source_port=source_port)
    rules = [r for r in collect_entries(dig(obj, "rules") if isinstance(obj, dict) and "rules" in obj else obj)
             if isinstance(r, dict)]
    return {"device": d.name, "matched": bool(rules), "first_match": rules[0] if rules else None, "all_matches": rules,
            "test": {"source": source, "destination": destination, "from_zone": from_zone, "to_zone": to_zone,
                     "protocol": protocol, "destination_port": destination_port, "source_port": source_port},
            "note": "result of the firewall's own nat-policy-match test"}


def _members(v):
    return [str(x) for x in as_list(v)] if v is not None else []


def _rule_row(e: dict) -> dict:
    return {"name": e.get("name"), "from": _members(e.get("from")), "to": _members(e.get("to")),
            "source": _members(e.get("source")), "destination": _members(e.get("destination")),
            "application": _members(e.get("application")), "service": _members(e.get("service")),
            "action": e.get("action"), "disabled": e.get("disabled"), "description": e.get("description"),
            "tags": _members(e.get("tag")), "log_end": e.get("log-end"), "profile_group": dig(e, "profile-setting", "group"),
            "source_translation": e.get("source-translation"), "destination_translation": e.get("destination-translation")}


async def list_rules(inv: Inventory, client: PanosClient, device: str, rule_type: str = "security",
                     name_contains: str | None = None, application: str | None = None, action: str | None = None,
                     address_contains: str | None = None, device_group: str | None = None, rulebase: str = "pre",
                     limit: int = 100) -> dict:
    check_limit(limit)
    check_text(name_contains, "name_contains")
    check_text(address_contains, "address_contains")
    if rule_type not in ("security", "nat"):
        raise ValidationError("rule_type must be security or nat")
    if rulebase not in ("pre", "post"):
        raise ValidationError("rulebase must be pre or post (Panorama only)")
    d = inv.resolve(device)
    if d.kind == "panorama":
        if not device_group:
            raise ValidationError("device_group is required for a Panorama")
        section = f"{rulebase}_{rule_type}_rules"
    else:
        section = f"{rule_type}_rules"
    obj = await client.config_get(d, section, dg=device_group)
    rows = [_rule_row(e) for e in collect_entries(dig(obj, "rules") if isinstance(obj, dict) and "rules" in obj else obj)
            if isinstance(e, dict)]
    total = len(rows)
    if name_contains:
        rows = [r for r in rows if name_contains.lower() in str(r["name"]).lower()]
    if application:
        rows = [r for r in rows if application in r["application"] or "any" in r["application"]]
    if action:
        rows = [r for r in rows if str(r["action"]).lower() == action.lower()]
    if address_contains:
        needle = address_contains.lower()
        rows = [r for r in rows if any(needle in x.lower() for x in r["source"] + r["destination"])]
    shown, note = clip(rows, limit)
    out = {"device": d.name, "rule_type": rule_type, "rules_in_rulebase": total, "matched": len(rows),
           "returned": len(shown), "rules": shown,
           "note": "rules are in evaluation order; a firewall managed by Panorama also receives Panorama's pre and post "
                   "rules, which are listed on the Panorama (with device_group), not here"}
    if note:
        out["note_more"] = note
    if not total and obj:
        out["parse_warnings"] = ["no rules recognised in the response"]
    return out


async def get_config_section(inv: Inventory, client: PanosClient, device: str, section: str,
                             name_contains: str | None = None, device_group: str | None = None,
                             vsys: str | None = None, limit: int = 100) -> dict:
    check_limit(limit)
    check_text(name_contains, "name_contains")
    if section not in XPATHS:
        raise ValidationError("section must be one of " + ", ".join(sorted(XPATHS)))
    d = inv.resolve(device)
    if section in PANORAMA_ONLY and d.kind != "panorama":
        raise ValidationError(f"{section} is only available on a Panorama")
    if section in NEEDS_DG and not device_group:
        raise ValidationError("device_group is required for this section")
    if device_group:
        validate_dg(device_group)
    if vsys:
        validate_vsys(vsys)
    obj = await client.config_get(d, section, vsys=vsys, dg=device_group)
    redacted = redaction_enabled()
    count = [0]
    if redacted:
        obj = redact_obj(obj, count)
    rows = [e for e in collect_entries(obj) if isinstance(e, dict)]
    out = {"device": d.name, "section": section, "redacted": redacted}
    if redacted:
        out["redactions"] = count[0]
    if rows and len(rows) > 1 or (rows and name_contains):
        if name_contains:
            rows = [r for r in rows if name_contains.lower() in str(r.get("name", "")).lower()]
        shown, note = clip(rows, limit)
        out.update({"entries_found": len(rows), "returned": len(shown), "entries": shown})
        if note:
            out["note"] = note
    else:
        out["data"] = obj
    if obj is None:
        out["note"] = "the section is empty or does not exist on this device"
    return out


def _fit(lines: list[str]) -> list[str]:
    """Keep the reply small enough for a small-context model; the caller pages on with offset."""
    out, size = [], 0
    for ln in lines:
        size += len(ln) + 1
        if size > MAX_OUTPUT_CHARS:
            break
        out.append(ln)
    return out


async def get_config(inv: Inventory, client: PanosClient, device: str, search: str | None = None, context: int = 2,
                     offset: int | None = None, limit: int = DEFAULT_LINES) -> dict:
    check_limit(limit, MAX_LINES)
    check_text(search, "search")
    if not isinstance(context, int) or isinstance(context, bool) or not 0 <= context <= 5:
        raise ValidationError("context must be 0-5")
    if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
        raise ValidationError("offset must be 0 or more")
    d = inv.resolve(device)
    raw = await client.export_config(d)
    redacted = redaction_enabled()
    lines, count = _pretty_lines(raw, redacted)
    if redacted:
        text, extra = redact_xml_text(chr(10).join(lines))        # second pass catches anything the tree walk did not
        lines, count = text.splitlines(), count + extra
    out = {"device": d.name, "total_lines": len(lines), "redacted": redacted}
    if redacted:
        out["redactions"] = count
    if search:
        needle = search.lower()
        found = [i for i, ln in enumerate(lines) if needle in ln.lower()]
        keep = sorted({j for i in found for j in range(max(0, i - context), min(len(lines), i + context + 1))})
        picked = _fit([f"{i + 1}: {lines[i]}" for i in keep[:limit]])
        out.update({"mode": "search", "matches": len(found), "lines": picked})
        if len(keep) > len(picked):
            out["truncated"] = f"{len(keep) - len(picked)} more lines; narrow the search"
    else:
        start = offset or 0
        picked = _fit([f"{i + 1}: {lines[i]}" for i in range(start, min(len(lines), start + limit))])
        out.update({"mode": "lines", "offset": start, "lines": picked})
        if start + len(picked) < len(lines):
            out["truncated"] = f"{len(lines) - start - len(picked)} more lines; continue with offset={start + len(picked)}"
    out["note"] = ("running configuration exported as XML" +
                   ("; secrets are redacted by element name on a best-effort basis" if redacted
                    else "; returned unfiltered, so it contains sensitive values such as password hashes"))
    return out
