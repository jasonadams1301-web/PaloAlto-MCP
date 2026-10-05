"""Turn the firewalls a Panorama manages into inventory entries for DIRECT connections, pinning each device certificate.

This is an administrator tool, run on the server (import-panorama.py). It is not an MCP tool, so an agent cannot change the
device list. It works in two steps: a review (prints every device, its certificate fingerprint and any problems, and a
review code), then a write that applies only what was reviewed: if any certificate has changed since, the code no longer
matches and nothing is written. Entries are appended, so existing ones and their comments are untouched."""
import asyncio
import hashlib
import os
import re
import socket
import ssl
import tempfile
import time

import yaml

from app.adapters.panos import pinned_context
from app.validation import NAME_RE, SERIAL_RE, Inventory, validate_ip


def sanitize_name(hostname) -> str | None:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", str(hostname or "").strip()).strip("-._")[:64]
    return name if name and NAME_RE.fullmatch(name) else None


# ---------------- certificate probing ----------------
def _fetch_der(host: str, port: int, timeout: float) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        return s.getpeercert(binary_form=True)


def _verify_pinned(host: str, port: int, pem: str, timeout: float) -> dict:
    """Connect again trusting ONLY this certificate, exactly as the server will. Returns its details, or raises ssl.SSLError."""
    ctx = pinned_context(cadata=pem)
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        return s.getpeercert()


def _why(e: Exception) -> str:
    t = str(e)
    if "certificate has expired" in t:
        return "certificate has expired"
    if "unsuitable certificate purpose" in t:
        return "certificate was generated as a CA-only certificate and cannot be used for the web interface"
    if "not yet valid" in t:
        return "certificate is not valid yet"
    return "certificate cannot be verified as a trust anchor (" + t.split("]")[-1].strip()[:80] + ")"


def probe_sync(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """What the server would see if it pinned this device: fingerprint, subject, expiry, and whether pinning will work."""
    try:
        der = _fetch_der(host, port, timeout)
    except Exception as e:
        return {"ok": False, "reachable": False, "reason": f"cannot connect to {host}:{port} ({type(e).__name__})"}
    pem = ssl.DER_cert_to_PEM_cert(der)
    fp = hashlib.sha256(der).hexdigest().upper()
    out = {"reachable": True, "pem": pem, "fingerprint": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))}
    try:
        info = _verify_pinned(host, port, pem, timeout)
    except ssl.SSLError as e:
        return {**out, "ok": False, "reason": _why(e)}
    except Exception as e:
        return {**out, "ok": False, "reason": f"second connection failed ({type(e).__name__})"}
    flat = lambda rdn: ", ".join(f"{k}={v}" for part in rdn for k, v in part)
    cn = next((v for part in info.get("subject", ()) for k, v in part if k == "commonName"), None)
    out.update({"ok": True, "subject": flat(info.get("subject", ())), "issuer": flat(info.get("issuer", ())),
                "common_name": cn, "not_after": info.get("notAfter")})
    return out


async def probe_all(hosts: dict[str, str], parallel: int = 8) -> dict[str, dict]:
    sem = asyncio.Semaphore(parallel)

    async def one(key, host):
        async with sem:
            return key, await asyncio.to_thread(probe_sync, host)

    return dict(await asyncio.gather(*(one(k, h) for k, h in hosts.items())))


# ---------------- planning ----------------
def plan(rows: list[dict], existing_names: set[str], existing_serials: set[str], existing_addresses: set[str]) -> dict:
    """Decide what could be added. `rows` are Panorama's device rows (serial, hostname, ip_address, model, device_group...)."""
    names, serials, addrs = ({x.lower() for x in s} for s in (existing_names, existing_serials, existing_addresses))
    add, skipped, problems = [], [], []
    for r in rows:
        serial, host = str(r.get("serial") or ""), r.get("hostname")
        label = host or serial or "(unnamed)"
        addr = str(r.get("ip_address") or "")
        if not SERIAL_RE.fullmatch(serial):
            problems.append({"device": label, "reason": "no usable serial number"})
            continue
        if serial.lower() in serials or addr.lower() in addrs:
            skipped.append({"device": label, "reason": "already in the inventory"})
            continue
        try:
            validate_ip(addr, "address")
        except Exception:
            problems.append({"device": label, "serial": serial, "reason": "Panorama reports no usable management IP"})
            continue
        name = sanitize_name(host)
        if not name:
            problems.append({"device": label, "serial": serial, "reason": "hostname cannot be used as a name"})
            continue
        if name.lower() in names:
            problems.append({"device": label, "serial": serial, "reason": f"name {name} is already used by another device"})
            continue
        names.add(name.lower())
        entry = {"name": name, "kind": "firewall", "address": addr, "serial": serial}
        if r.get("device_group"):
            entry["site"] = str(r["device_group"])
        if r.get("model"):
            entry["model"] = str(r["model"])
        entry["tls"] = "pinned"
        entry["mcp_enabled"] = True
        add.append(entry)
    return {"add": add, "skipped": skipped, "problems": problems}


def review_code(items: list[tuple[str, str]]) -> str:
    """A short code over (name, certificate fingerprint) pairs. Writing needs the code from the review, so only
    certificates a person has seen can be pinned."""
    text = "\n".join(f"{n.lower()}={fp}" for n, fp in sorted(items))
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def render(entries: list[dict]) -> str:
    text = yaml.safe_dump(entries, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return "".join("  " + ln + "\n" for ln in text.splitlines())


def apply(path: str, cert_dir: str, entries: list[dict], pems: dict[str, str]) -> str:
    """Write the certificates and append the entries, checking that the inventory still loads with exactly that many more
    devices. Keeps a backup; on any failure the new certificates are removed and the inventory is left as it was."""
    with open(path, encoding="utf-8") as f:
        original = f.read()
    before = len(Inventory.load(path).all())
    new_text = (original if original.endswith("\n") else original + "\n") + render(entries)
    st = os.stat(path)
    backup = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    written: list[str] = []
    tmp = None
    try:
        with open(backup, "w", encoding="utf-8") as f:
            f.write(original)
        os.chmod(backup, st.st_mode & 0o777)
        for e in entries:
            target = os.path.join(cert_dir, f"{e['name']}.pem")
            with open(target, "w", encoding="utf-8") as f:
                f.write(pems[e["name"]])
            written.append(target)
            os.chmod(target, 0o640)
            if hasattr(os, "chown"):
                os.chown(target, 0, st.st_gid)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_text)
        os.chmod(tmp, st.st_mode & 0o777)
        if hasattr(os, "chown"):
            os.chown(tmp, st.st_uid, st.st_gid)
        after = len(Inventory.load(tmp).all())
        if after != before + len(entries):
            raise ValueError(f"inventory check failed: expected {before + len(entries)} devices, found {after}")
        os.replace(tmp, path)
        tmp = None
    except Exception:
        for t in written:
            if os.path.exists(t):
                os.unlink(t)
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return backup



# ---------------- refreshing existing pins ----------------
def pem_fingerprint(pem: str) -> str:
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def days_until(not_after: str | None, now: float | None = None) -> int | None:
    try:
        return int((ssl.cert_time_to_seconds(not_after) - (now if now is not None else time.time())) // 86400)
    except Exception:
        return None


def refresh_status(old_pem: str | None, probe: dict, now: float | None = None) -> dict:
    """Compare a device's current certificate with the one pinned. state is one of:
    unchanged, changed (new certificate verifies and can be pinned), bad (new certificate unusable), unreachable, unpinned."""
    if not probe.get("reachable"):
        return {"state": "unreachable", "reason": probe.get("reason")}
    old_fp = pem_fingerprint(old_pem) if old_pem else None
    out = {"old_fingerprint": old_fp, "new_fingerprint": probe["fingerprint"],
           "days_left": days_until(probe.get("not_after"), now), "not_after": probe.get("not_after"),
           "common_name": probe.get("common_name"), "subject": probe.get("subject"), "issuer": probe.get("issuer")}
    if old_fp is None:
        return {**out, "state": "unpinned", "reason": "no pinned certificate on file"}
    if probe["fingerprint"] == old_fp:
        return {**out, "state": "unchanged"}
    if not probe.get("ok"):
        return {**out, "state": "bad", "reason": probe.get("reason")}
    return {**out, "state": "changed"}


def apply_refresh(cert_dir: str, updates: dict[str, str]) -> list[str]:
    """Replace pinned certificates. The old file is kept as <name>.pem.bak-<time>; on any failure everything is put back."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    done: list[tuple[str, str | None]] = []                     # (path, backup path or None)
    try:
        for name, pem in updates.items():
            path = os.path.join(cert_dir, f"{name}.pem")
            backup = None
            if os.path.exists(path):
                backup = f"{path}.bak-{stamp}"
                with open(path, encoding="utf-8") as f, open(backup, "w", encoding="utf-8") as g:
                    g.write(f.read())
                os.chmod(backup, os.stat(path).st_mode & 0o777)
            fd, tmp = tempfile.mkstemp(dir=cert_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(pem)
            if os.path.exists(path):
                st = os.stat(path)
                os.chmod(tmp, st.st_mode & 0o777)
                if hasattr(os, "chown"):
                    os.chown(tmp, st.st_uid, st.st_gid)
            os.replace(tmp, path)
            done.append((path, backup))
    except Exception:
        for path, backup in done:
            if backup and os.path.exists(backup):
                os.replace(backup, path)
            elif os.path.exists(path):
                os.unlink(path)
        raise
    return [b for _, b in done if b]
