"""XML safety, the fixed command table, inventory rules and the API client (against a fake device)."""
import asyncio
import os
import pathlib
import ssl

import httpx
import pytest

from app.adapters.panos import PanosClient, PanosError, make_ssl_context
from app.commands import (ALLOWED_ROOTS, LICENSE_QUERY, OPS, XPATHS, build_log_query, build_op, build_xpath)
from app.validation import Inventory, ValidationError, validate_ip_or_cidr, validate_port, validate_protocol
from app.xmlutil import XmlError, as_list, build_command, dig, parse_response, to_obj

DATA = pathlib.Path(__file__).parent / "data"


def write_inventory(tmp_path):
    p = tmp_path / "inv.yaml"
    p.write_text("""
devices:
  - {name: pan1, kind: panorama, address: pan1.example, site: HQ, mcp_enabled: true}
  - {name: fw-managed, kind: firewall, via: pan1, serial: "0123456789", site: HQ, model: PA-440, mcp_enabled: true}
  - {name: fw-edge, kind: firewall, address: fw-edge.example, credential: edge, tls: ca, mcp_enabled: true}
  - {name: disabled-fw, kind: firewall, address: x.example, mcp_enabled: false}
""", encoding="utf-8")
    return Inventory.load(str(p))


@pytest.fixture
def inv(tmp_path):
    return write_inventory(tmp_path)


# ---------------- XML building and parsing ----------------
def test_values_are_escaped_and_cannot_add_elements():
    xml = build_command(("show", "session", "all", "filter"), children=(("source", "</source><set><x/></set>&"),))
    root = parse_response("<response status='success'><result>" + xml + "</result></response>").result
    filt = root.find("show/session/all/filter")
    assert [c.tag for c in filt] == ["source"] and "<set>" in filt.find("source").text      # it stayed text
    assert "&lt;/source&gt;" in xml and "<set>" not in xml


def test_parse_response_success_error_and_message_lines():
    ok = parse_response('<response status="success"><result><a>1</a></result></response>')
    assert ok.status == "success" and ok.result.find("a").text == "1"
    err = parse_response('<response status="error" code="13"><msg><line>Object not found</line></msg></response>')
    assert err.status == "error" and err.code == "13" and err.message == "Object not found"


@pytest.mark.parametrize("bad", ["not xml", "<other/>", "<!DOCTYPE r [<!ENTITY x 'y'>]><response status='success'/>",
                                 '<!DOCTYPE lolz [<!ENTITY lol "lol">]><response status="success"><result>&lol;</result></response>'])
def test_hostile_or_malformed_xml_is_rejected(bad):
    with pytest.raises(XmlError):
        parse_response(bad)


def test_to_obj_shapes():
    xml = ("<result><hw><entry name='ethernet1/1'><state>up</state></entry><entry name='ethernet1/2'><state>down</state>"
           "</entry></hw><zones><member>trust</member><member>untrust</member></zones><n>5</n><n>6</n><empty/></result>")
    obj = to_obj(parse_response(f'<response status="success">{xml}</response>').result)
    assert obj["hw"] == [{"name": "ethernet1/1", "state": "up"}, {"name": "ethernet1/2", "state": "down"}]
    assert obj["zones"] == ["trust", "untrust"] and obj["n"] == ["5", "6"] and obj["empty"] is None
    assert dig(obj, "hw", 1, "state") == "down" and dig(obj, "nope", "x", default="d") == "d"
    assert as_list(None) == [] and as_list("a") == ["a"] and as_list(["a"]) == ["a"]


def test_oversized_trees_are_refused():
    deep = "<a>" * 40 + "x" + "</a>" * 40
    with pytest.raises(XmlError):
        to_obj(parse_response(f'<response status="success"><result>{deep}</result></response>').result)


# ---------------- the fixed command table ----------------
def test_every_operational_command_is_show_test_or_the_license_query():
    for key, op in OPS.items():
        assert op.path[0] in ALLOWED_ROOTS or op.path == LICENSE_QUERY, key
    assert LICENSE_QUERY == ("request", "license", "info")
    forbidden = {"set", "edit", "delete", "commit", "load", "import", "debug", "clear", "rename", "move"}
    assert all(not set(op.path) & forbidden for op in OPS.values())


def test_exact_xml_for_known_commands():
    assert build_op("system_info") == "<show><system><info /></system></show>"
    assert build_op("interfaces") == "<show><interface>all</interface></show>"
    assert build_op("interface_one", name="ethernet1/1") == "<show><interface>ethernet1/1</interface></show>"
    assert build_op("route_lookup", virtual_router="default", ip="8.8.8.8") == (
        "<test><routing><fib-lookup><virtual-router>default</virtual-router><ip>8.8.8.8</ip></fib-lookup></routing></test>")
    assert build_op("policy_match", from_zone="trust", to_zone="untrust", source="10.0.0.5", destination="8.8.8.8",
                    destination_port=443, protocol="tcp", application="ssl") == (
        "<test><security-policy-match><from>trust</from><to>untrust</to><source>10.0.0.5</source>"
        "<destination>8.8.8.8</destination><destination-port>443</destination-port><protocol>6</protocol>"
        "<application>ssl</application></security-policy-match></test>")
    assert build_op("session_all", source="10.0.0.0/24", destination_port=22, state="ACTIVE") == (
        "<show><session><all><filter><source>10.0.0.0/24</source><destination-port>22</destination-port>"
        "<state>active</state></filter></all></session></show>")


@pytest.mark.parametrize("key,params", [
    ("nope", {}), ("system_info", {"x": "1"}), ("interface_one", {}), ("interface_one", {"name": "eth1/1; reload"}),
    ("session_all", {"source": "10.0.0.1; drop"}), ("session_all", {"destination_port": 70000}),
    ("session_all", {"state": "weird"}), ("session_all", {"application": "ssl' or 1=1"}),
    ("session_all", {"from_zone": "trust</from><set>"}), ("policy_match", {"source": "10.0.0.0/24"}),
    ("nat_match", {"destination": "not-an-ip"}), ("route_lookup", {"ip": "999.1.1.1"}),
    ("counters_global", {"severity": "critical"}), ("session_all", {"protocol": "gre-ish"})])
def test_bad_commands_and_values_are_rejected(key, params):
    with pytest.raises(ValidationError):
        build_op(key, **params)


def test_config_xpaths_substitute_only_validated_names():
    assert build_xpath("security_rules", "vsys2") == (
        "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']/rulebase/security/rules")
    assert build_xpath("pre_security_rules", dg="Branch DG").endswith(
        "/device-group/entry[@name='Branch DG']/pre-rulebase/security/rules")
    bad_calls = [("nope", {}), ("security_rules", {"vsys": "vsys1']/../.."}), ("pre_security_rules", {}),
                 ("pre_security_rules", {"dg": "x']|//*['"})]
    for section, kwargs in bad_calls:
        with pytest.raises(ValidationError):
            build_xpath(section, **kwargs)


def test_log_queries_are_built_from_validated_pieces():
    q = build_log_query("1h", source="10.0.0.0/24", destination="8.8.8.8", application="ssl", action="deny",
                        rule="Allow web", destination_port=443, from_zone="trust", to_zone="untrust", severity="high")
    assert q == ("(receive_time in last-hour) and (addr.src in 10.0.0.0/24) and (addr.dst in 8.8.8.8) and (app eq 'ssl') "
                 "and (action eq 'deny') and (rule eq 'Allow web') and (port.dst eq 443) and (zone.src eq 'trust') "
                 "and (zone.dst eq 'untrust') and (severity eq 'high')")
    for bad in ({"window": "1y"}, {"window": "1h", "application": "x') or ('1'='1"}, {"window": "1h", "rule": "a'b"},
                {"window": "1h", "action": "exec"}, {"window": "1h", "source": "10.0.0.1 or 1"},
                {"window": "1h", "destination_port": 0}):
        with pytest.raises(ValidationError):
            build_log_query(**bad)


def test_value_validators():
    assert validate_ip_or_cidr("10.0.0.5") == "10.0.0.5" and validate_ip_or_cidr("10.0.0.0/24") == "10.0.0.0/24"
    assert validate_port("443") == "443" and validate_protocol("UDP") == "17" and validate_protocol(47) == "47"
    for fn, bad in ((validate_ip_or_cidr, "10.0.0.256"), (validate_port, True), (validate_port, "0"), (validate_protocol, "256")):
        with pytest.raises(ValidationError):
            fn(bad)


# ---------------- inventory ----------------
def test_inventory_loads_only_enabled_devices_and_resolves_names_only(inv):
    assert [d.name for d in inv.all()] == ["fw-edge", "fw-managed", "pan1"]
    assert inv.resolve("FW-MANAGED").via == "pan1" and inv.endpoint(inv.resolve("fw-managed")).name == "pan1"
    for bad in ("198.51.100.9", "disabled-fw", "x; y", ""):
        with pytest.raises(ValidationError):
            inv.resolve(bad)
    with pytest.raises(ValidationError):
        inv.resolve("fw-edge", kind="panorama")


@pytest.mark.parametrize("entry", [
    "{name: a, kind: firewall, via: ghost, serial: '0123456789', mcp_enabled: true}",
    "{name: a, kind: firewall, via: fw1, serial: '0123456789', mcp_enabled: true}",
    "{name: b, kind: panorama, via: pan1, serial: '0123456789', mcp_enabled: true}",
    "{name: c, kind: firewall, via: pan1, mcp_enabled: true}",
    "{name: d, kind: firewall, mcp_enabled: true}",
    "{name: e, kind: switch, address: x.example, mcp_enabled: true}",
    "{name: f, kind: firewall, address: x.example, tls: none, mcp_enabled: true}",
    "{name: 'bad name', kind: firewall, address: x.example, mcp_enabled: true}"])
def test_bad_inventory_entries_fail_at_load(tmp_path, entry):
    p = tmp_path / "i.yaml"
    p.write_text("devices:\n  - {name: pan1, kind: panorama, address: p.example, mcp_enabled: true}\n"
                 "  - {name: fw1, kind: firewall, address: f.example, mcp_enabled: true}\n  - " + entry + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        Inventory.load(str(p))


# ---------------- API client against a fake device ----------------
class FakeDevice:
    def __init__(self, responses=None):
        self.requests, self.responses = [], responses or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = dict(x.split("=", 1) for x in request.content.decode().split("&") if "=" in x)
        self.requests.append({"host": request.url.host, "path": request.url.path, "query": request.url.query.decode(),
                              "key": request.headers.get("x-pan-key"), "form": form})
        handler = self.responses.get(form.get("type"))
        body = handler(form) if callable(handler) else handler
        if isinstance(body, httpx.Response):
            return body
        return httpx.Response(200, text=body)


OK = '<response status="success"><result><system><hostname>fw1</hostname><model>PA-440</model></system></result></response>'


def client(inv, fake, monkeypatch, **env):
    monkeypatch.setenv("PANOS_KEY_PANORAMA", "key-for-panorama")
    monkeypatch.setenv("PANOS_KEY_FIREWALL", "key-for-firewall")
    monkeypatch.setenv("PANOS_KEY_EDGE", "key-for-edge")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return PanosClient(inv, transport=httpx.MockTransport(fake))


async def test_key_goes_in_a_header_never_in_the_url_or_body(inv, monkeypatch):
    fake = FakeDevice({"op": OK})
    c = client(inv, fake, monkeypatch)
    out = await c.op(inv.resolve("fw-edge"), "system_info")
    r = fake.requests[0]
    assert out == {"system": {"hostname": "fw1", "model": "PA-440"}} or out["system"]["hostname"] == "fw1"
    assert r["host"] == "fw-edge.example" and r["path"] == "/api/" and r["key"] == "key-for-edge"
    assert "key-for" not in r["query"] and not any("key-for" in v for v in r["form"].values())
    assert r["form"]["type"] == "op" and "target" not in r["form"]


async def test_managed_firewall_is_queried_through_panorama_with_its_target_serial(inv, monkeypatch):
    fake = FakeDevice({"op": OK})
    await client(inv, fake, monkeypatch).op(inv.resolve("fw-managed"), "system_info")
    r = fake.requests[0]
    assert r["host"] == "pan1.example" and r["key"] == "key-for-panorama" and r["form"]["target"] == "0123456789"


async def test_missing_key_is_a_clear_error_without_any_request(inv, monkeypatch):
    fake = FakeDevice({"op": OK})
    c = client(inv, fake, monkeypatch)
    monkeypatch.delenv("PANOS_KEY_EDGE")
    with pytest.raises(PanosError, match="no credentials are configured"):
        await c.op(inv.resolve("fw-edge"), "system_info")
    assert fake.requests == []


@pytest.mark.parametrize("response,match", [
    ('<response status="error" code="13"><msg><line>Object not found</line></msg></response>', "Object not found"),
    ("<html>login</html>", "valid XML|unexpected"),
    (httpx.Response(403, text="forbidden"), "rejected the credentials"),
    (httpx.Response(500, text="oops"), "HTTP 500")])
async def test_error_responses_become_clear_errors(inv, monkeypatch, response, match):
    c = client(inv, FakeDevice({"op": lambda form: response}), monkeypatch)
    with pytest.raises(PanosError, match=match):
        await c.op(inv.resolve("fw-edge"), "system_info")


async def test_oversized_responses_are_refused(inv, monkeypatch):
    c = client(inv, FakeDevice({"op": "<response status='success'><result>" + "x" * 5000 + "</result></response>"}),
               monkeypatch, PANOS_MAX_RESPONSE_BYTES="1000")
    with pytest.raises(PanosError, match="too large"):
        await c.op(inv.resolve("fw-edge"), "system_info")


async def test_config_get_and_export(inv, monkeypatch):
    fake = FakeDevice({"config": '<response status="success" code="19"><result><rules><entry name="r1"/></rules></result></response>',
                       "export": "<config><devices/></config>"})
    c = client(inv, fake, monkeypatch)
    out = await c.config_get(inv.resolve("fw-edge"), "security_rules")
    assert out == {"rules": [{"name": "r1"}]} or out["rules"] == {"name": "r1"} or out["rules"][0]["name"] == "r1"
    assert fake.requests[0]["form"]["action"] == "get" and "rulebase%2Fsecurity" in fake.requests[0]["form"]["xpath"]
    assert await c.export_config(inv.resolve("fw-edge")) == "<config><devices/></config>"
    assert fake.requests[1]["form"] == {"type": "export", "category": "configuration"}


async def test_log_search_polls_until_the_job_finishes(inv, monkeypatch):
    state = {"polls": 0}

    def logs(form):
        if form.get("action") == "get":
            state["polls"] += 1
            if state["polls"] < 3:
                return '<response status="success"><result><job><status>ACT</status></job></result></response>'
            return ('<response status="success"><result><job><status>FIN</status></job><log><logs count="2">'
                    '<entry><src>10.0.0.1</src><action>deny</action></entry><entry><src>10.0.0.2</src><action>allow</action>'
                    '</entry></logs></log></result></response>')
        return '<response status="success"><result><msg><line>job enqueued with jobid 77</line></msg><job>77</job></result></response>'

    fake = FakeDevice({"log": logs})
    entries = await client(inv, fake, monkeypatch).log_search(inv.resolve("fw-edge"), "traffic", "(app eq 'ssl')", 20)
    assert [e["src"] for e in entries] == ["10.0.0.1", "10.0.0.2"] and state["polls"] == 3
    assert fake.requests[0]["form"]["log-type"] == "traffic" and fake.requests[1]["form"]["job-id"] == "77"


async def test_log_search_with_no_matches_and_a_stuck_job(inv, monkeypatch):
    empty = '<response status="success"><result><job><status>FIN</status></job><log><logs count="0"/></log></result></response>'
    first = '<response status="success"><result><job>5</job></result></response>'
    c = client(inv, FakeDevice({"log": lambda f: empty if f.get("action") == "get" else first}), monkeypatch)
    assert await c.log_search(inv.resolve("fw-edge"), "traffic", "q", 5) == []
    stuck = '<response status="success"><result><job><status>ACT</status></job></result></response>'
    c = client(inv, FakeDevice({"log": lambda f: stuck if f.get("action") == "get" else first}), monkeypatch)
    with pytest.raises(PanosError, match="did not finish in time"):
        await c.log_search(inv.resolve("fw-edge"), "traffic", "q", 5, max_wait=0.3)


# ---------------- TLS pinning ----------------
def test_pinned_mode_needs_the_devices_own_certificate(inv, tmp_path):
    with pytest.raises(PanosError, match="no pinned certificate"):
        make_ssl_context(inv.resolve("pan1"), str(tmp_path), None)


def test_pinned_context_verifies_and_trusts_only_that_certificate(inv, tmp_path):
    import shutil
    import ssl
    shutil.copy(DATA / "pinned_test_cert.pem", tmp_path / "pan1.pem")
    ctx = make_ssl_context(inv.resolve("pan1"), str(tmp_path), None)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is False
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert len(ctx.get_ca_certs()) == 1                                    # exactly the pinned certificate, nothing else


def test_ca_mode_uses_normal_verification(inv):
    ctx = make_ssl_context(inv.resolve("fw-edge"), "/nonexistent", None)
    import ssl
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


async def test_tls_failure_inside_connect_error_is_reported_as_tls(inv, monkeypatch):
    def boom(request):
        err = httpx.ConnectError("x")
        err.__cause__ = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unsuitable certificate purpose")
        raise err
    c = client(inv, boom, monkeypatch)
    with pytest.raises(PanosError, match="CA-only certificate"):
        await c.op(inv.resolve("fw-edge"), "system_info")


def test_log_query_with_a_start_time_is_validated():
    assert build_log_query(None, since="2026/10/05 11:42:35", application="ssl") ==         "(receive_time geq '2026/10/05 11:42:35') and (app eq 'ssl')"
    for bad in ("2026/10/05", "2026-10-05 11:42:35", "2026/10/05 11:42:35' or (1=1", "x", 5):
        with pytest.raises(ValidationError):
            build_log_query(None, since=bad)
    with pytest.raises(ValidationError):
        build_log_query("1h", since="2026/10/05 11:42:35")
