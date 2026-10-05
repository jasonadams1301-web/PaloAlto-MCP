"""Panorama import: planning, review code, writing (with rollback), and certificate probing against local TLS servers."""
import datetime
import os
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import importer
from app.validation import Inventory


def row(serial="0123456789", host="fw-one", ip="10.1.1.1", **kw):
    return {"serial": serial, "hostname": host, "ip_address": ip, "model": "PA-440", "device_group": "Branch", **kw}


def test_sanitize_name():
    assert importer.sanitize_name("FW One (DR)") == "FW-One-DR"
    assert importer.sanitize_name("fw.edge_1") == "fw.edge_1"
    assert importer.sanitize_name("") is None and importer.sanitize_name(None) is None and importer.sanitize_name("***") is None


def test_plan_adds_skips_and_reports_problems():
    rows = [row(), row("A" * 8, "fw-two", "10.1.1.2", device_group=None, model=None),
            row("B" * 8, "known", "10.1.1.3"),                        # serial already in the inventory
            row("C" * 8, "other", "10.9.9.9"),                       # address already in the inventory
            row("D" * 8, "taken", "10.1.1.4"),                       # name already used
            row("E" * 8, "fw-one", "10.1.1.5"),                      # duplicate of a name earlier in this same batch
            row("F" * 8, "noip", ""), row("12", "badserial", "10.1.1.6"), row("G" * 8, "???", "10.1.1.7")]
    p = importer.plan(rows, {"taken"}, {"b" * 8}, {"10.9.9.9"})
    assert [e["name"] for e in p["add"]] == ["fw-one", "fw-two"]
    assert p["add"][0] == {"name": "fw-one", "kind": "firewall", "address": "10.1.1.1", "serial": "0123456789",
                           "site": "Branch", "model": "PA-440", "tls": "pinned", "mcp_enabled": True}
    assert "site" not in p["add"][1] and "model" not in p["add"][1]
    assert {x["device"] for x in p["skipped"]} == {"known", "other"}
    reasons = {x["device"]: x["reason"] for x in p["problems"]}
    assert "already used" in reasons["taken"] and "already used" in reasons["fw-one"] and "no usable" in reasons["badserial"]
    assert "management IP" in reasons["noip"] and "cannot be used as a name" in reasons["???"]


def test_review_code_depends_on_names_and_fingerprints_not_order():
    a = importer.review_code([("one", "AA"), ("two", "BB")])
    assert a == importer.review_code([("two", "BB"), ("ONE", "AA")])
    assert a != importer.review_code([("one", "AA"), ("two", "CC")]) and a != importer.review_code([("one", "AA")])
    assert len(a) == 12


INV = """# approved devices (keep this comment)
devices:
  - name: pan1
    kind: panorama
    address: pan.example
    tls: ca
    mcp_enabled: true
  - name: existing
    kind: firewall
    address: 10.9.9.9
    mcp_enabled: true
"""


def test_apply_appends_keeps_comments_pins_certs_and_backs_up(tmp_path):
    inv, certs = tmp_path / "inventory.yaml", tmp_path / "certs"
    inv.write_text(INV, encoding="utf-8")
    certs.mkdir()
    entries = importer.plan([row(), row("A" * 8, "fw-two", "10.1.1.2")], set(), set(), set())["add"]
    backup = importer.apply(str(inv), str(certs), entries, {"fw-one": "PEM-ONE\n", "fw-two": "PEM-TWO\n"})
    text = inv.read_text(encoding="utf-8")
    assert text.startswith("# approved devices (keep this comment)") and open(backup, encoding="utf-8").read() == INV
    loaded = {d.name: d for d in Inventory.load(str(inv)).all()}
    assert set(loaded) == {"pan1", "existing", "fw-one", "fw-two"}
    assert loaded["fw-one"].address == "10.1.1.1" and loaded["fw-one"].serial == "0123456789" and loaded["fw-one"].tls == "pinned"
    assert (certs / "fw-one.pem").read_text() == "PEM-ONE\n" and (certs / "fw-two.pem").read_text() == "PEM-TWO\n"


def test_apply_rolls_back_certificates_and_inventory_on_failure(tmp_path):
    inv, certs = tmp_path / "inventory.yaml", tmp_path / "certs"
    inv.write_text(INV, encoding="utf-8")
    certs.mkdir()
    good = {"name": "fw-ok", "kind": "firewall", "address": "10.1.1.1", "serial": "0123456789", "tls": "pinned", "mcp_enabled": True}
    bad = {**good, "name": "fw bad name", "address": "10.1.1.2"}                      # fails inventory validation
    with pytest.raises(ValueError):
        importer.apply(str(inv), str(certs), [good, bad], {"fw-ok": "A", "fw bad name": "B"})
    assert inv.read_text(encoding="utf-8") == INV and os.listdir(certs) == []
    assert [f for f in os.listdir(tmp_path) if f.startswith("tmp")] == []


# ---------------- certificate probing against real local TLS servers ----------------
def make_cert(tmp_path, name, *, ca=False, expired=False, server_usage=True):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    start, end = (now - datetime.timedelta(days=400), now - datetime.timedelta(days=30)) if expired else (
        now - datetime.timedelta(days=1), now + datetime.timedelta(days=365))
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, False, False, False), critical=True)
    if server_usage:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    cert = b.sign(key, hashes.SHA256())
    c, k = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(c), str(k)


class TlsServer:
    def __init__(self, certfile, keyfile):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.ctx, self.stop = ctx, False
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except Exception:
                pass

    def close(self):
        self.stop = True
        self.sock.close()


@pytest.fixture
def serve(tmp_path):
    servers = []

    def start(name, **kw):
        s = TlsServer(*make_cert(tmp_path, name, **kw))
        servers.append(s)
        return s.port
    yield start
    for s in servers:
        s.close()


def test_probe_accepts_a_normal_self_signed_certificate(serve):
    r = importer.probe_sync("127.0.0.1", serve("good"), timeout=5)
    assert r["ok"] and r["reachable"] and r["subject"] == "commonName=127.0.0.1" and r["common_name"] == "127.0.0.1" and r["pem"].startswith("-----BEGIN CERT")
    assert len(r["fingerprint"].split(":")) == 32


def test_probe_flags_ca_only_and_expired_certificates(serve):
    r = importer.probe_sync("127.0.0.1", serve("ca", ca=True, server_usage=False), timeout=5)
    assert not r["ok"] and r["reachable"] and "CA-only" in r["reason"] and r["fingerprint"]
    r = importer.probe_sync("127.0.0.1", serve("old", expired=True), timeout=5)
    assert not r["ok"] and "expired" in r["reason"]


def test_probe_reports_unreachable():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = importer.probe_sync("127.0.0.1", port, timeout=2)
    assert not r["ok"] and not r["reachable"] and "cannot connect" in r["reason"]


async def test_probe_all_runs_in_parallel_and_keys_results_by_name(serve):
    ok, ca = serve("a"), serve("b", ca=True, server_usage=False)
    orig = importer.probe_sync
    importer.probe_sync = lambda host, port=443, timeout=8.0: orig("127.0.0.1", {"x": ok, "y": ca}[host], 5)
    try:
        res = await importer.probe_all({"one": "x", "two": "y"})
    finally:
        importer.probe_sync = orig
    assert res["one"]["ok"] and not res["two"]["ok"]


# ---------------- refreshing pins ----------------
def pem_of(tmp_path, name, **kw):
    return open(make_cert(tmp_path, name, **kw)[0], encoding="utf-8").read()


def probe_of(pem, **kw):
    return {"reachable": True, "ok": True, "pem": pem, "fingerprint": importer.pem_fingerprint(pem),
            "not_after": "Jan  1 00:00:00 2099 GMT", "common_name": "127.0.0.1", **kw}


def test_refresh_status_classifies_each_case(tmp_path):
    old, new = pem_of(tmp_path, "old"), pem_of(tmp_path, "new")
    assert importer.refresh_status(old, probe_of(old))["state"] == "unchanged"
    st = importer.refresh_status(old, probe_of(new))
    assert st["state"] == "changed" and st["old_fingerprint"] != st["new_fingerprint"] and st["days_left"] > 1000
    bad = importer.refresh_status(old, probe_of(new, ok=False, reason="certificate has expired"))
    assert bad["state"] == "bad" and "expired" in bad["reason"]
    assert importer.refresh_status(old, {"reachable": False, "ok": False, "reason": "cannot connect"})["state"] == "unreachable"
    assert importer.refresh_status(None, probe_of(new))["state"] == "unpinned"


def test_days_until():
    assert importer.days_until("Jan  1 00:00:00 2000 GMT") < 0
    assert importer.days_until("garbage") is None and importer.days_until(None) is None


def test_apply_refresh_replaces_keeps_backup_and_rolls_back(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "a.pem").write_text("OLD-A")
    (certs / "b.pem").write_text("OLD-B")
    backups = importer.apply_refresh(str(certs), {"a": "NEW-A", "b": "NEW-B"})
    assert (certs / "a.pem").read_text() == "NEW-A" and (certs / "b.pem").read_text() == "NEW-B"
    assert sorted(open(b).read() for b in backups) == ["OLD-A", "OLD-B"]
    # a failure part-way puts everything back: the second name makes the write fail (directory in its place)
    (certs / "c.pem").write_text("OLD-C")
    (certs / "d.pem").mkdir()
    with pytest.raises(Exception):
        importer.apply_refresh(str(certs), {"c": "NEW-C", "d": "NEW-D"})
    assert (certs / "c.pem").read_text() == "OLD-C" and (certs / "d.pem").is_dir()
