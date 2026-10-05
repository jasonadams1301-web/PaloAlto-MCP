"""Inventory allowlist and input validation. Nothing reaches a device unless it passes here.

Every value that ends up inside an XML command or a log filter is validated against a strict pattern first, and
is also placed into the XML as text (never by string formatting), so an agent cannot inject extra elements."""
import ipaddress
import re
from dataclasses import dataclass

import yaml

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
SERIAL_RE = re.compile(r"[0-9A-Za-z]{6,20}")
CRED_RE = re.compile(r"[a-z0-9_]{1,32}")
ZONE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}")
APP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
RULE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}")
VR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
VSYS_RE = re.compile(r"vsys[0-9]{1,3}")
DG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}")
IFACE_RE = re.compile(r"[a-z]+[0-9]*(?:/[0-9]+)*(?:\.[0-9]+)?")
KINDS = ("panorama", "firewall")
TLS_MODES = ("pinned", "ca")


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Device:
    name: str
    kind: str                       # panorama | firewall
    address: str                    # API endpoint host/IP (unused for firewalls managed through Panorama)
    via: str | None = None          # name of the Panorama that manages this firewall
    serial: str | None = None       # firewall serial (needed with via)
    site: str = ""
    model: str = ""
    tls: str = "pinned"             # pinned: trust exactly the device's own certificate; ca: normal CA verification
    credential: str | None = None   # optional named API key (panos_key_<name>); default is by kind
    vsys: str = "vsys1"


class Inventory:
    def __init__(self, devices: list[Device]):
        self._by_name = {d.name.lower(): d for d in devices}
        for d in devices:
            if d.via:
                p = self._by_name.get(d.via.lower())
                if p is None or p.kind != "panorama":
                    raise ValueError(f"device {d.name}: via must name a Panorama in the inventory, not {d.via!r}")

    @classmethod
    def load(cls, path: str) -> "Inventory":
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        devices = []
        for e in data.get("devices", []):
            if e.get("mcp_enabled") is not True:
                continue
            name, kind = str(e["name"]), str(e.get("kind", "firewall")).lower()
            if not NAME_RE.fullmatch(name):
                raise ValueError(f"invalid device name {name!r}")
            if kind not in KINDS:
                raise ValueError(f"device {name}: kind must be one of {', '.join(KINDS)}")
            via = str(e["via"]) if e.get("via") else None
            serial = str(e["serial"]) if e.get("serial") else None
            address = str(e.get("address", "") or "")
            if via:
                if kind != "firewall":
                    raise ValueError(f"device {name}: only firewalls can be managed via a Panorama")
                if not serial or not SERIAL_RE.fullmatch(serial):
                    raise ValueError(f"device {name}: a serial number is required with via")
            elif not address or not HOST_RE.fullmatch(address):
                raise ValueError(f"device {name}: a valid address is required")
            tls = str(e.get("tls", "pinned")).lower()
            if tls not in TLS_MODES:
                raise ValueError(f"device {name}: tls must be one of {', '.join(TLS_MODES)}")
            cred = str(e["credential"]).lower() if e.get("credential") else None
            if cred and not CRED_RE.fullmatch(cred):
                raise ValueError(f"device {name}: credential must be lowercase letters, digits or _")
            vsys = str(e.get("vsys", "vsys1"))
            if not VSYS_RE.fullmatch(vsys):
                raise ValueError(f"device {name}: invalid vsys {vsys!r}")
            devices.append(Device(name=name, kind=kind, address=address, via=via, serial=serial,
                                  site=str(e.get("site", "") or ""), model=str(e.get("model", "") or ""),
                                  tls=tls, credential=cred, vsys=vsys))
        return cls(devices)

    def all(self) -> list[Device]:
        return sorted(self._by_name.values(), key=lambda d: d.name)

    def resolve(self, name: str, kind: str | None = None) -> Device:
        """Resolve a device by inventory name only. IPs and arbitrary hostnames are rejected."""
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ValidationError("invalid device name")
        d = self._by_name.get(name.lower())
        if d is None:
            raise ValidationError("device is not in the approved inventory")
        if kind and d.kind != kind:
            raise ValidationError(f"this tool only works on a {kind}")
        return d

    def endpoint(self, d: Device) -> Device:
        """The device whose address, certificate and API key are used: the managing Panorama for a managed firewall."""
        return self._by_name[d.via.lower()] if d.via else d

    def lookup(self, name) -> "Device | None":
        """Like resolve() but returns None instead of raising (used only for labelling results)."""
        return self._by_name.get(name.lower()) if isinstance(name, str) else None


# ---------------- value validators (used by tools before anything is sent) ----------------
def _text(value, rx: re.Pattern, label: str) -> str:
    if not isinstance(value, str) or not rx.fullmatch(value):
        raise ValidationError(f"invalid {label}")
    return value


def validate_ip(value: str, label: str = "address") -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except (ValueError, TypeError):
        raise ValidationError(f"{label} must be an IPv4 address") from None


def validate_ip_or_cidr(value: str, label: str = "address") -> str:
    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except (ValueError, TypeError):
        raise ValidationError(f"{label} must be an IPv4 address or network such as 192.0.2.0/24") from None
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def validate_port(value, label: str = "port") -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit() or not 1 <= int(value) <= 65535:
        raise ValidationError(f"{label} must be 1-65535")
    return str(int(value))


PROTOCOLS = {"tcp": "6", "udp": "17", "icmp": "1"}


def validate_protocol(value) -> str:
    if isinstance(value, str) and value.lower() in PROTOCOLS:
        return PROTOCOLS[value.lower()]
    if isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= 255:
        raise ValidationError("protocol must be tcp, udp, icmp or a number 1-255")
    return str(int(value))


def validate_zone(value: str, label: str = "zone") -> str:
    return _text(value, ZONE_RE, label)


def validate_app(value: str) -> str:
    return _text(value, APP_RE, "application")


def validate_rule(value: str) -> str:
    return _text(value, RULE_RE, "rule name")


def validate_vr(value: str) -> str:
    return _text(value, VR_RE, "virtual router")


def validate_vsys(value: str) -> str:
    return _text(value, VSYS_RE, "vsys (expected vsys1, vsys2, ...)")


def validate_dg(value: str) -> str:
    return _text(value, DG_RE, "device group")


def validate_interface(value: str) -> str:
    return _text(value, IFACE_RE, "interface (expected e.g. ethernet1/1, ae1.10, tunnel.1)")
