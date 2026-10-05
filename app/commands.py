"""The fixed set of PAN-OS API requests this server can make. Nothing else can be sent.

- Operational commands (`type=op`) are limited to `show` and `test` trees, plus the single read-only licence query.
  There is no `set`, `edit`, `delete`, `commit`, `import`, `load`, `debug` or other `request`.
- Configuration reads (`type=config&action=get`) use fixed XPaths; only validated names are substituted into them.
- Log searches are built from structured, validated filters (see build_log_query).
Callers pass a command KEY and validated parameters; they never supply XML, XPath or filter text."""
from dataclasses import dataclass

from app.validation import (ValidationError, validate_app, validate_dg, validate_interface, validate_ip,
                            validate_ip_or_cidr, validate_port, validate_protocol, validate_rule, validate_vr,
                            validate_vsys, validate_zone)
from app.xmlutil import build_command

ALLOWED_ROOTS = ("show", "test")
LICENSE_QUERY = ("request", "license", "info")           # the only non-show/test operational command


@dataclass(frozen=True)
class Op:
    path: tuple[str, ...]
    text: str | None = None                  # fixed leaf text such as "all"
    param_text: str | None = None            # name of the parameter whose (validated) value is the leaf text
    children: tuple[str, ...] = ()           # parameters that become child elements, in this order
    tags: tuple[tuple[str, str], ...] = ()   # parameter name -> XML tag when it differs (from_zone -> from)


OPS: dict[str, Op] = {
    "system_info": Op(("show", "system", "info")),
    "system_resources": Op(("show", "system", "resources")),
    "disk_space": Op(("show", "system", "disk-space")),
    "ha_state": Op(("show", "high-availability", "state")),
    "licenses": Op(LICENSE_QUERY),
    "jobs": Op(("show", "jobs", "all")),
    "interfaces": Op(("show", "interface"), text="all"),
    "interface_one": Op(("show", "interface"), param_text="name"),
    "counters_interface": Op(("show", "counter", "interface"), text="all"),
    "counters_global": Op(("show", "counter", "global", "filter"), children=("delta", "severity")),
    "routes": Op(("show", "routing", "route")),
    "route_lookup": Op(("test", "routing", "fib-lookup"), children=("virtual_router", "ip"),
                       tags=(("virtual_router", "virtual-router"),)),
    "session_info": Op(("show", "session", "info")),
    "session_all": Op(("show", "session", "all", "filter"),
                      children=("source", "destination", "destination_port", "source_port", "application", "protocol",
                                "from_zone", "to_zone", "rule", "state"),
                      tags=(("destination_port", "destination-port"), ("source_port", "source-port"),
                            ("from_zone", "from"), ("to_zone", "to"))),
    "vpn_ike_sa": Op(("show", "vpn", "ike-sa")),
    "vpn_ipsec_sa": Op(("show", "vpn", "ipsec-sa")),
    "vpn_flow": Op(("show", "vpn", "flow")),
    "gp_users": Op(("show", "global-protect-gateway", "current-user")),
    "policy_match": Op(("test", "security-policy-match"),
                       children=("from_zone", "to_zone", "source", "destination", "destination_port", "protocol",
                                 "application"),
                       tags=(("from_zone", "from"), ("to_zone", "to"), ("destination_port", "destination-port"))),
    "nat_match": Op(("test", "nat-policy-match"),
                    children=("from_zone", "to_zone", "source", "destination", "destination_port", "source_port",
                              "protocol"),
                    tags=(("from_zone", "from"), ("to_zone", "to"), ("destination_port", "destination-port"),
                          ("source_port", "source-port"))),
    "panorama_connected": Op(("show", "devices", "connected")),
    "panorama_all": Op(("show", "devices", "all")),
}

# parameter validators (every value is checked before it is placed into the XML)
SESSION_STATES = ("active", "closed", "discard", "init", "opening")
COUNTER_SEVERITIES = ("drop", "error", "warn", "info")
VALIDATORS = {
    "name": validate_interface, "virtual_router": validate_vr, "ip": validate_ip,
    "source": validate_ip_or_cidr, "destination": validate_ip_or_cidr,
    "destination_port": validate_port, "source_port": validate_port,
    "application": validate_app, "protocol": validate_protocol,
    "from_zone": validate_zone, "to_zone": validate_zone, "rule": validate_rule,
    "state": lambda v: _choice(v, SESSION_STATES, "state"),
    "delta": lambda v: _choice(v, ("yes", "no"), "delta"),
    "severity": lambda v: _choice(v, COUNTER_SEVERITIES, "severity"),
}
# policy/NAT tests need a single host, not a network
SINGLE_HOST_PARAMS = {"policy_match": ("source", "destination"), "nat_match": ("source", "destination")}


def _choice(value, allowed, label):
    if not isinstance(value, str) or value.lower() not in allowed:
        raise ValidationError(f"{label} must be one of {', '.join(allowed)}")
    return value.lower()


def build_op(key: str, **params) -> str:
    """Render a fixed operational command. Unknown keys and unknown, missing or invalid parameters are rejected."""
    op = OPS.get(key)
    if op is None:
        raise ValidationError("command is not in the approved list")
    allowed = set(op.children) | ({op.param_text} if op.param_text else set())
    unknown = set(params) - allowed
    if unknown:
        raise ValidationError(f"unexpected parameter(s): {', '.join(sorted(unknown))}")
    given = {k: v for k, v in params.items() if v is not None}
    if op.param_text and op.param_text not in given:
        raise ValidationError(f"{op.param_text} is required")
    tag_of = dict(op.tags)
    children = []
    for p in op.children:
        if p in given:
            val = VALIDATORS[p](given[p])
            if p in SINGLE_HOST_PARAMS.get(key, ()):
                val = validate_ip(given[p], p)
            children.append((tag_of.get(p, p.replace("_", "-")), val))
    text = op.text
    if op.param_text:
        text = VALIDATORS[op.param_text](given[op.param_text])
    return build_command(op.path, text=text, children=tuple(children))


# ---------------- configuration reads (fixed XPaths) ----------------
_DEV = "/config/devices/entry[@name='localhost.localdomain']"
_VSYS = _DEV + "/vsys/entry[@name='{vsys}']"
_DG = _DEV + "/device-group/entry[@name='{dg}']"
XPATHS: dict[str, str] = {
    "security_rules": _VSYS + "/rulebase/security/rules",
    "nat_rules": _VSYS + "/rulebase/nat/rules",
    "address_objects": _VSYS + "/address",
    "address_groups": _VSYS + "/address-group",
    "services": _VSYS + "/service",
    "service_groups": _VSYS + "/service-group",
    "zones": _VSYS + "/zone",
    "interfaces": _DEV + "/network/interface",
    "virtual_routers": _DEV + "/network/virtual-router",
    "ha": _DEV + "/deviceconfig/high-availability",
    "system_settings": _DEV + "/deviceconfig/system",
    "certificates": "/config/shared/certificate",
    # Panorama
    "device_groups": _DEV + "/device-group",
    "templates": _DEV + "/template",
    "pre_security_rules": _DG + "/pre-rulebase/security/rules",
    "post_security_rules": _DG + "/post-rulebase/security/rules",
    "pre_nat_rules": _DG + "/pre-rulebase/nat/rules",
    "post_nat_rules": _DG + "/post-rulebase/nat/rules",
}
PANORAMA_ONLY = {"device_groups", "templates", "pre_security_rules", "post_security_rules", "pre_nat_rules",
                 "post_nat_rules"}
NEEDS_DG = {"pre_security_rules", "post_security_rules", "pre_nat_rules", "post_nat_rules"}


def build_xpath(key: str, vsys: str = "vsys1", dg: str | None = None) -> str:
    tmpl = XPATHS.get(key)
    if tmpl is None:
        raise ValidationError("config section is not in the approved list")
    vsys = validate_vsys(vsys)
    if key in NEEDS_DG:
        if dg is None:
            raise ValidationError("device_group is required for this section")
        dg = validate_dg(dg)
    return tmpl.format(vsys=vsys, dg=dg or "")


# ---------------- logs ----------------
LOG_TYPES = ("traffic", "threat", "system", "config", "url", "wildfire", "globalprotect", "userid", "auth")
LOG_WINDOWS = {"15m": "last-15-minutes", "1h": "last-hour", "6h": "last-6-hrs", "24h": "last-24-hrs", "7d": "last-7-days"}
LOG_ACTIONS = ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both", "alert", "block-ip", "block-url")
LOG_SEVERITIES = ("informational", "low", "medium", "high", "critical")


def build_log_query(window: str, source=None, destination=None, application=None, action=None, rule=None,
                    destination_port=None, from_zone=None, to_zone=None, severity=None) -> str:
    """Structured log filter. Values are validated first; none can contain quotes or parentheses."""
    if window not in LOG_WINDOWS:
        raise ValidationError("window must be one of " + ", ".join(LOG_WINDOWS))
    clauses = [f"(receive_time in {LOG_WINDOWS[window]})"]
    if source:
        clauses.append(f"(addr.src in {validate_ip_or_cidr(source, 'source')})")
    if destination:
        clauses.append(f"(addr.dst in {validate_ip_or_cidr(destination, 'destination')})")
    if application:
        clauses.append(f"(app eq '{validate_app(application)}')")
    if action:
        clauses.append(f"(action eq '{_choice(action, LOG_ACTIONS, 'action')}')")
    if rule:
        clauses.append(f"(rule eq '{validate_rule(rule)}')")
    if destination_port is not None:
        clauses.append(f"(port.dst eq {validate_port(destination_port, 'destination_port')})")
    if from_zone:
        clauses.append(f"(zone.src eq '{validate_zone(from_zone, 'from_zone')}')")
    if to_zone:
        clauses.append(f"(zone.dst eq '{validate_zone(to_zone, 'to_zone')}')")
    if severity:
        clauses.append(f"(severity eq '{_choice(severity, LOG_SEVERITIES, 'severity')}')")
    return " and ".join(clauses)


# ---------------- self-check at import: nothing but show/test (and the licence query) can ever be built ----------------
for _key, _op in OPS.items():
    assert _op.path[0] in ALLOWED_ROOTS or _op.path == LICENSE_QUERY, f"{_key}: not a read-only command"
assert all(not set(op.path) & {"set", "edit", "delete", "commit", "load", "import", "debug", "clear", "rename"}
           for op in OPS.values())
