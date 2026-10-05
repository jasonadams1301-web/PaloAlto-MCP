"""All 24 tools, against a fake PAN-OS device that answers with documented-style XML (synthetic data)."""
import json
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

import httpx
import pytest

from app.adapters.panos import PanosClient
from app.audit import Audit
from app.main import build_server
from app.validation import Inventory

NOW = datetime.now(timezone.utc)


def wrap(inner):
    return f'<response status="success"><result>{inner}</result></response>'


def fmt(days):
    d = NOW + timedelta(days=days)
    return f"{d:%B} {d.day}, {d.year}"


SYSINFO = wrap("<system><hostname>fw-edge</hostname><ip-address>192.0.2.10</ip-address><model>PA-440</model>"
               "<serial>0123456789</serial><sw-version>11.1.2</sw-version><app-version>8800-8500</app-version>"
               "<threat-version>8800-8500</threat-version><av-version>4800-5000</av-version><uptime>12 days, 3:04:05</uptime>"
               "<multi-vsys>off</multi-vsys><operational-mode>normal</operational-mode></system>")
RESOURCES = wrap("<![CDATA[top - 10:00:00 up 12 days,  3:04,  1 user,  load average: 0.52, 0.48, 0.45\nTasks: 200 total\n"
                 "%Cpu(s):  5.0 us,  2.0 sy,  0.0 ni, 92.0 id,  1.0 wa\nMiB Mem :   8000.0 total,   2000.0 free,   3000.0 used,   3000.0 buff/cache\n]]>")
DISK = wrap("<![CDATA[Filesystem      Size  Used Avail Use% Mounted on\n/dev/root       7.0G  3.0G  4.0G  43% /\n/dev/sda5       9.0G  8.6G  0.4G  96% /opt/pancfg\n]]>")
HA_OK = wrap("<enabled>yes</enabled><group><mode>Active-Passive</mode><local-info><state>active</state><preemptive>no</preemptive>"
             "</local-info><peer-info><state>passive</state><conn-status>up</conn-status></peer-info>"
             "<running-sync>synchronized</running-sync></group>")
HA_BAD = HA_OK.replace("synchronized", "not synchronized").replace("<state>passive", "<state>suspended")
LICENSES = wrap(f"<licenses><entry><feature>Threat Prevention</feature><expires>{fmt(400)}</expires><expired>no</expired></entry>"
                f"<entry><feature>PAN-DB URL Filtering</feature><expires>January 1, 2020</expires><expired>yes</expired></entry>"
                f"<entry><feature>GlobalProtect</feature><expires>{fmt(20)}</expires><expired>no</expired></entry>"
                "<entry><feature>Support</feature><expires>Never</expires><expired>no</expired></entry></licenses>")
CERTS = wrap("<certificate><entry name='web-ok'><common-name>fw.example</common-name><ca>no</ca><algorithm>RSA</algorithm>"
             f"<expiry-epoch>{int(time.time()) + 400 * 86400}</expiry-epoch></entry>"
             f"<entry name='web-old'><common-name>old.example</common-name><expiry-epoch>{int(time.time()) - 5 * 86400}</expiry-epoch></entry>"
             f"<entry name='vpn-soon'><common-name>vpn.example</common-name><expiry-epoch>{int(time.time()) + 10 * 86400}</expiry-epoch></entry>"
             "</certificate>")
JOBS = wrap("<job><id>11</id><type>Downld</type><status>FIN</status><result>OK</result></job>"
            "<job><id>12</id><type>Commit</type><status>FIN</status><result>FAIL</result><details><line>Validation error</line></details></job>")
IFACES = wrap("<ifnet><entry><name>ethernet1/1</name><zone>untrust</zone><fwd>vr:default</fwd><vsys>1</vsys><ip>203.0.113.2/29</ip><tag>0</tag></entry>"
              "<entry><name>ethernet1/2</name><zone>trust</zone><fwd>vr:default</fwd><vsys>1</vsys><ip>10.0.0.1/24</ip></entry>"
              "<entry><name>tunnel.1</name><zone>vpn</zone><ip>N/A</ip></entry></ifnet>"
              "<hw><entry><name>ethernet1/1</name><state>up</state><speed>1000</speed><duplex>full</duplex><mac>02:00:00:00:00:01</mac></entry>"
              "<entry><name>ethernet1/2</name><state>down</state><speed>ukn</speed><duplex>ukn</duplex></entry></hw>")
COUNTERS_IF = wrap("<ifnet><entry><name>ethernet1/1</name><ibytes>1000</ibytes><obytes>2000</obytes><ipackets>10</ipackets>"
                   "<opackets>20</opackets><ierrors>0</ierrors><idrops>0</idrops></entry>"
                   "<entry><name>ethernet1/2</name><ibytes>5</ibytes><obytes>6</obytes><ipackets>1</ipackets><opackets>2</opackets>"
                   "<ierrors>7</ierrors><idrops>3</idrops></entry></ifnet>"
                   "<hw><entry><name>ethernet1/1</name><rx-error>0</rx-error></entry></hw>")
COUNTERS_GLOBAL = wrap("<global><counters><rate>10</rate><entry><name>flow_policy_deny</name><value>120</value><rate>2</rate>"
                       "<severity>drop</severity><category>flow</category><aspect>session</aspect><desc>denied by policy</desc></entry>"
                       "<entry><name>flow_fwd_l3_norarp</name><value>900</value><rate>5</rate><severity>drop</severity>"
                       "<category>flow</category><aspect>forward</aspect><desc>no ARP</desc></entry>"
                       "<entry><name>zero_one</name><value>0</value><rate>0</rate><severity>drop</severity></entry></counters></global>")
ROUTES = wrap("<flags>A:active, S:static</flags><entry><virtual-router>default</virtual-router><destination>0.0.0.0/0</destination>"
              "<nexthop>203.0.113.1</nexthop><metric>10</metric><flags>A S</flags><interface>ethernet1/1</interface>"
              "<route-table>unicast</route-table></entry><entry><virtual-router>default</virtual-router>"
              "<destination>10.0.0.0/24</destination><nexthop>10.0.0.1</nexthop><metric>0</metric><flags>A C</flags>"
              "<interface>ethernet1/2</interface></entry><entry><virtual-router>guest</virtual-router>"
              "<destination>0.0.0.0/0</destination><nexthop>192.0.2.1</nexthop><metric>10</metric><flags>A S</flags></entry>")
FIB = wrap("<nh>ip</nh><src>203.0.113.2</src><ip>203.0.113.1</ip><metric>10</metric><interface>ethernet1/1</interface><dp>dp0</dp>")
SESSINFO = wrap("<num-active>8500</num-active><num-max>10000</num-max><num-tcp>8000</num-tcp><num-udp>480</num-udp>"
                "<num-icmp>20</num-icmp><pps>1000</pps><cps>50</cps><kbps>5000</kbps>")
SESSINFO_LOW = SESSINFO.replace("8500", "1500")
SESSIONS = wrap("<entry><idx>1</idx><application>ssl</application><source>10.0.0.5</source><dst>8.8.8.8</dst><sport>51000</sport>"
                "<dport>443</dport><state>ACTIVE</state></entry><entry><idx>2</idx><application>ssl</application>"
                "<source>10.0.0.6</source><dst>8.8.8.8</dst><sport>51001</sport><dport>443</dport><state>ACTIVE</state></entry>")
IKE = wrap("<entry><name>gw-branch</name><state>up</state></entry><entry><name>gw-partner</name><state>init</state></entry>")
IPSEC = wrap("<entries><entry><name>tun-branch</name><state>active</state></entry><entry><name>tun-partner</name><state>down</state></entry></entries>")
GP = wrap("<entry><username>alice</username><computer>pc-alice</computer><client>Windows</client></entry>"
          "<entry><username>bob</username><computer>pc-bob</computer><client>macOS</client></entry>")
POLMATCH = wrap("<rules><entry name='Allow web'><index>3</index><action>allow</action><from>trust</from><to>untrust</to></entry>"
                "<entry name='Allow any'><index>9</index><action>allow</action></entry></rules>")
POLMATCH_NONE = wrap("<rules/>")
NATMATCH = wrap("<rules><entry name='Outbound PAT'><index>1</index><source-translation>dynamic-ip-and-port</source-translation></entry></rules>")
DEVICES = wrap("<devices><entry><serial>0123456789</serial><hostname>fw-managed</hostname><ip-address>192.0.2.20</ip-address>"
               "<model>PA-440</model><sw-version>11.1.2</sw-version><connected>yes</connected><ha><state>active</state></ha></entry>"
               "<entry><serial>9999999999</serial><hostname>fw-unknown</hostname><model>PA-220</model><connected>yes</connected></entry></devices>")
SECRULES = wrap("<rules><entry name='Allow web'><from><member>trust</member></from><to><member>untrust</member></to>"
                "<source><member>10.0.0.0/24</member></source><destination><member>any</member></destination>"
                "<application><member>ssl</member><member>web-browsing</member></application><service><member>application-default</member></service>"
                "<action>allow</action></entry><entry name='Block bad'><from><member>any</member></from><to><member>any</member></to>"
                "<source><member>any</member></source><destination><member>bad-hosts</member></destination>"
                "<application><member>any</member></application><service><member>any</member></service><action>deny</action>"
                "<description>block known bad</description></entry><entry name='Old rule'><from><member>any</member></from>"
                "<to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination>"
                "<application><member>any</member></application><service><member>any</member></service><action>allow</action>"
                "<disabled>yes</disabled></entry></rules>")
ADDR = wrap("<address><entry name='web1'><ip-netmask>10.0.0.10/32</ip-netmask></entry><entry name='web2'><ip-netmask>10.0.0.11/32</ip-netmask></entry>"
            "<entry name='db1'><ip-netmask>10.0.1.10/32</ip-netmask></entry></address>")
SYSCFG = wrap("<system><hostname>fw-edge</hostname><dns-setting><servers><primary>192.0.2.53</primary></servers></dns-setting>"
              "<snmp-setting><access-setting><version><v2c><snmp-community-string>Pu8l1cC0mm</snmp-community-string></v2c></version></access-setting></snmp-setting></system>")
CONFIG_XML = ("<config version=\"11.1.0\">\n  <mgt-config>\n    <users>\n      <entry name=\"admin\">\n        <phash>$5$abc$secrethashvalue</phash>\n"
              "      </entry>\n    </users>\n  </mgt-config>\n  <devices>\n    <entry name=\"localhost.localdomain\">\n"
              "      <deviceconfig>\n        <system>\n          <hostname>fw-edge</hostname>\n          <ntp-servers><primary-ntp-server><ntp-server-address>192.0.2.123</ntp-server-address></primary-ntp-server></ntp-servers>\n"
              "          <snmp-setting><snmp-community-string>Pu8l1cC0mm</snmp-community-string></snmp-setting>\n        </system>\n"
              "      </deviceconfig>\n      <network>\n        <ike><gateway><entry name=\"gw1\"><authentication><pre-shared-key><key>AQ==PskSecretValue</key></pre-shared-key></authentication></entry></gateway></ike>\n"
              "      </network>\n    </entry>\n  </devices>\n</config>\n")
SECRETS = ["secrethashvalue", "Pu8l1cC0mm", "PskSecretValue"]

OPS = [("<show><system><info", SYSINFO), ("<show><system><resources", RESOURCES), ("<show><system><disk-space", DISK),
       ("<show><high-availability><state", HA_OK), ("<request><license><info", LICENSES), ("<show><jobs><all", JOBS),
       ("<show><interface>all", IFACES), ("<show><counter><interface>", COUNTERS_IF), ("<show><counter><global>", COUNTERS_GLOBAL),
       ("<show><routing><route", ROUTES), ("<test><routing><fib-lookup", FIB), ("<show><session><info", SESSINFO),
       ("<show><session><all>", SESSIONS), ("<show><vpn><ike-sa", IKE), ("<show><vpn><ipsec-sa", IPSEC),
       ("<show><global-protect-gateway>", GP), ("<test><security-policy-match>", POLMATCH),
       ("<test><nat-policy-match>", NATMATCH), ("<show><devices>", DEVICES)]
CONFIGS = [("deviceconfig/system", SYSCFG), ("shared/certificate", CERTS), ("pre-rulebase/security/rules", SECRULES),
           ("rulebase/security/rules", SECRULES), ("rulebase/nat/rules", wrap("<rules/>")), ("/address", ADDR),
           ("/device-group", wrap("<device-group><entry name='Branch'/></device-group>"))]


class Fake:
    def __init__(self, ops=None, configs=None):
        self.ops, self.configs, self.requests = list(ops or OPS), list(configs or CONFIGS), []

    def override(self, marker, body):
        self.ops = [(m, body if m == marker else b) for m, b in self.ops]

    def __call__(self, request):
        form = dict(parse_qsl(request.content.decode()))
        self.requests.append({"host": request.url.host, "form": form, "key": request.headers.get("x-pan-key")})
        t = form.get("type")
        if t == "op":
            for marker, body in self.ops:
                if marker in form["cmd"]:
                    return httpx.Response(200, text=body)
            return httpx.Response(200, text='<response status="error" code="12"><msg><line>Invalid command</line></msg></response>')
        if t == "config":
            for marker, body in self.configs:
                if marker in form["xpath"]:
                    return httpx.Response(200, text=body)
            return httpx.Response(200, text='<response status="success" code="7"><result/></response>')
        if t == "export":
            return httpx.Response(200, text=CONFIG_XML)
        if t == "log":
            if form.get("action") == "get":
                return httpx.Response(200, text=wrap("<job><status>FIN</status></job><log><logs count='2'>"
                                                     "<entry><src>10.0.0.5</src><dst>8.8.8.8</dst><dport>443</dport><app>ssl</app><action>allow</action><rule>Allow web</rule><extra>x</extra></entry>"
                                                     "<entry><src>10.0.0.6</src><dst>8.8.4.4</dst><dport>53</dport><app>dns</app><action>deny</action></entry></logs></log>"))
            return httpx.Response(200, text=wrap("<msg><line>job enqueued with jobid 5</line></msg><job>5</job>"))
        return httpx.Response(400, text="bad")

    def cmds(self):
        return [r["form"].get("cmd") or r["form"].get("xpath") or r["form"].get("query") for r in self.requests]


@pytest.fixture
def inv(tmp_path):
    p = tmp_path / "inv.yaml"
    p.write_text("""
devices:
  - {name: pan1, kind: panorama, address: pan1.example, site: HQ, model: M-200, mcp_enabled: true}
  - {name: fw-managed, kind: firewall, via: pan1, serial: "0123456789", site: HQ, model: PA-440, mcp_enabled: true}
  - {name: fw-edge, kind: firewall, address: fw-edge.example, site: Edge, model: PA-3220, credential: edge, tls: ca, mcp_enabled: true}
""", encoding="utf-8")
    return Inventory.load(str(p))


@pytest.fixture
def env(monkeypatch):
    for k, v in (("PANOS_KEY_PANORAMA", "kp"), ("PANOS_KEY_FIREWALL", "kf"), ("PANOS_KEY_EDGE", "ke")):
        monkeypatch.setenv(k, v)


def mk(inv, fake=None):
    fake = fake or Fake()
    return build_server(inv, PanosClient(inv, transport=httpx.MockTransport(fake)), Audit(None)), fake


async def call(mcp, tool, **args):
    res = await mcp.call_tool(tool, args)
    return json.loads(res[0].text)


EXPECTED = {"list_devices", "list_panorama_devices", "get_system_info", "get_resources", "get_disk_space", "get_ha_status",
            "get_licenses", "get_certificates", "get_jobs", "get_interfaces", "get_interface_counters", "get_drop_counters",
            "get_routes", "lookup_route", "get_session_info", "find_sessions", "get_vpn_status", "get_globalprotect_users",
            "search_logs", "policy_match", "nat_match", "list_rules", "get_config_section", "get_config"}


async def test_catalogue_is_exactly_the_read_only_tools(inv, env):
    mcp, _ = mk(inv)
    names = {t.name for t in await mcp.list_tools()}
    assert names == EXPECTED and len(names) == 24
    assert not any(n.startswith(("set", "edit", "delete", "commit", "import", "run", "exec", "load", "clear", "request"))
                   or "command" in n or "xml" in n for n in names)


async def test_devices_and_panorama_listing(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "list_devices")
    assert out["total_devices"] == 3 and {d["name"] for d in out["devices"]} == {"pan1", "fw-managed", "fw-edge"}
    assert (await call(mcp, "list_devices", kind="panorama"))["matched"] == 1
    assert (await call(mcp, "list_devices", site="edge"))["devices"][0]["name"] == "fw-edge"
    out = await call(mcp, "list_panorama_devices", panorama="pan1")
    assert out["devices_reported"] == 2 and out["not_in_inventory"] == 1 and out["managed_by"] is None
    assert {r["hostname"]: r["in_inventory_as"] for r in out["devices"]} == {"fw-managed": "fw-managed", "fw-unknown": None}
    with pytest.raises(Exception):
        await mcp.call_tool("list_panorama_devices", {"panorama": "fw-edge"})


async def test_results_are_labelled_and_managed_firewalls_go_through_panorama(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "get_system_info", device="fw-managed")
    assert out["kind"] == "firewall" and out["managed_by"] == "pan1" and out["hostname"] == "fw-edge"
    assert fake.requests[0]["host"] == "pan1.example" and fake.requests[0]["key"] == "kp"
    assert fake.requests[0]["form"]["target"] == "0123456789"
    out = await call(mcp, "get_system_info", device="fw-edge")
    assert fake.requests[1]["host"] == "fw-edge.example" and fake.requests[1]["key"] == "ke" and out["managed_by"] is None
    assert out["model"] == "PA-440" and out["sw_version"] == "11.1.2" and out["app_version"] == "8800-8500"


async def test_health_tools(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "get_resources", device="fw-edge")
    assert out["load_average"] == [0.52, 0.48, 0.45] and out["management_cpu_used_percent"] == 8.0
    assert out["management_memory_used_percent"] == 37.5
    out = await call(mcp, "get_disk_space", device="fw-edge")
    assert out["nearly_full"] and "/dev/sda5" in out["attention"][0]
    out = await call(mcp, "get_ha_status", device="fw-edge")
    assert out["ha_enabled"] is True and out["local_state"] == "active" and out["peer_state"] == "passive"
    assert out["running_sync"] == "synchronized" and out["attention"] == []
    fake.override("<show><high-availability><state", HA_BAD)
    out = await call(mcp, "get_ha_status", device="fw-edge")
    assert any("not synchronized" in a for a in out["attention"]) and any("suspended" in a for a in out["attention"])
    out = await call(mcp, "get_licenses", device="fw-edge")
    by = {r["feature"]: r for r in out["licenses"]}
    assert by["PAN-DB URL Filtering"]["expired"] is True and by["Threat Prevention"]["expired"] is False
    assert by["Support"]["days_left"] is None and 18 <= by["GlobalProtect"]["days_left"] <= 20
    assert any("PAN-DB" in a and "expired" in a for a in out["attention"]) and any("GlobalProtect" in a for a in out["attention"])
    out = await call(mcp, "get_certificates", device="fw-edge")
    assert [c["name"] for c in out["certificates"]] == ["web-old", "vpn-soon", "web-ok"]            # soonest first
    assert [a.split()[1] for a in out["attention"]] == ["web-old", "vpn-soon"]
    out = await call(mcp, "get_jobs", device="fw-edge")
    assert [j["id"] for j in out["jobs"]] == ["12", "11"] and out["failed_jobs"] == 1 and "failed" in out["attention"][0]


async def test_interfaces_and_counters(inv, env):
    mcp, _ = mk(inv)
    out = await call(mcp, "get_interfaces", device="fw-edge")
    by = {i["name"]: i for i in out["interfaces"]}
    assert by["ethernet1/1"]["state"] == "up" and by["ethernet1/1"]["zone"] == "untrust" and by["ethernet1/1"]["ip"] == "203.0.113.2/29"
    assert out["up"] == 1 and out["down"] == 1 and out["attention"] == ["interface ethernet1/2 is down but assigned to a zone"]
    assert [i["name"] for i in (await call(mcp, "get_interfaces", device="fw-edge", name_contains="tunnel"))["interfaces"]] == ["tunnel.1"]
    out = await call(mcp, "get_interface_counters", device="fw-edge", only_errors=True)
    assert [i["name"] for i in out["interfaces"]] == ["ethernet1/2"]
    assert out["interfaces"][0]["error_or_drop_counters"] == {"ierrors": 7, "idrops": 3}
    out = await call(mcp, "get_interface_counters", device="fw-edge", name="ethernet1/1")
    assert {i["table"] for i in out["interfaces"]} == {"ifnet", "hw"} and out["interfaces"][0]["counters"]["ibytes"] == "1000"
    with pytest.raises(Exception):
        await mcp.call_tool("get_interface_counters", {"device": "fw-edge", "name": "eth1/1; reload"})


async def test_drop_counters_and_validation(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "get_drop_counters", device="fw-edge")
    assert [c["name"] for c in out["counters"]] == ["flow_fwd_l3_norarp", "flow_policy_deny"] and out["counters_nonzero"] == 2
    assert "<delta>yes</delta><severity>drop</severity>" in fake.cmds()[0]
    for bad in ({"delta": "maybe"}, {"severity": "critical"}):
        with pytest.raises(Exception):
            await mcp.call_tool("get_drop_counters", {"device": "fw-edge", **bad})


async def test_routes_and_lookup(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "get_routes", device="fw-edge")
    assert out["routes_on_device"] == 3 and len(out["default_routes"]) == 2
    out = await call(mcp, "get_routes", device="fw-edge", virtual_router="default", destination_contains="10.0.0")
    assert [r["destination"] for r in out["routes"]] == ["10.0.0.0/24"]
    out = await call(mcp, "lookup_route", device="fw-edge", destination="8.8.8.8", virtual_router="default")
    assert [r["virtual_router"] for r in out["results"]] == ["default"] and out["results"][0]["interface"] == "ethernet1/1"
    assert "<virtual-router>default</virtual-router><ip>8.8.8.8</ip>" in fake.cmds()[-1]
    out = await call(mcp, "lookup_route", device="fw-edge", destination="8.8.8.8")          # no VR given: asks each one
    assert [r["virtual_router"] for r in out["results"]] == ["default", "guest"], out
    for bad in ({"destination": "8.8.8.8; drop"}, {"destination": "8.8.8.8", "virtual_router": "a b"}):
        with pytest.raises(Exception):
            await mcp.call_tool("lookup_route", {"device": "fw-edge", **bad})


async def test_sessions(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "get_session_info", device="fw-edge")
    assert out["utilization_percent"] == 85.0 and any("85.0% full" in a for a in out["attention"]) and out["tcp"] == 8000
    fake.override("<show><session><info", SESSINFO_LOW)
    assert (await call(mcp, "get_session_info", device="fw-edge"))["attention"] == []
    n = len(fake.requests)
    with pytest.raises(Exception, match="at least one filter"):
        await mcp.call_tool("find_sessions", {"device": "fw-edge"})
    assert len(fake.requests) == n                                              # refused before any request
    out = await call(mcp, "find_sessions", device="fw-edge", destination="8.8.8.8", destination_port=443, limit=1)
    assert out["sessions_found"] == 2 and out["returned"] == 1 and "more" in out["note"]
    assert "<destination>8.8.8.8</destination><destination-port>443</destination-port>" in fake.cmds()[-1]
    for bad in ({"source": "10.0.0.1; drop"}, {"application": "ssl' or 1=1"}, {"state": "weird"}, {"destination_port": 99999}):
        with pytest.raises(Exception):
            await mcp.call_tool("find_sessions", {"device": "fw-edge", **bad})


async def test_vpn_and_globalprotect(inv, env):
    mcp, _ = mk(inv)
    out = await call(mcp, "get_vpn_status", device="fw-edge")
    assert out["ike_gateways_found"] == 2 and out["ipsec_tunnels_found"] == 2
    assert set(out["attention"]) == {"IKE gateway gw-partner is init", "IPsec tunnel tun-partner is down"}
    out = await call(mcp, "get_globalprotect_users", device="fw-edge")
    assert out["users_connected"] == 2 and out["users"][0]["username"] == "alice"


async def test_search_logs(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "search_logs", device="fw-edge", window="6h", source="10.0.0.0/24", application="ssl", limit=2)
    assert out["returned"] == 2 and out["by_action"] == {"allow": 1, "deny": 1}
    assert "extra" not in out["logs"][0] and out["logs"][0]["rule"] == "Allow web"
    assert "note" in out                                                       # capped at the limit
    q = fake.requests[0]["form"]["query"]
    assert q == "(receive_time in last-6-hrs) and (addr.src in 10.0.0.0/24) and (app eq 'ssl')"
    assert fake.requests[0]["form"]["nlogs"] == "2" and fake.requests[0]["form"]["log-type"] == "traffic"
    n = len(fake.requests)
    for bad in ({"log_type": "everything"}, {"window": "1y"}, {"application": "x') or ('1'='1"}, {"rule": "a'b"},
                {"log_type": "system", "source": "10.0.0.1"}, {"log_type": "config", "action": "deny"},
                {"severity": "high"}, {"limit": 201}):
        with pytest.raises(Exception):
            await mcp.call_tool("search_logs", {"device": "fw-edge", **bad})
    assert len(fake.requests) == n
    out = await call(mcp, "search_logs", device="fw-edge", log_type="threat", severity="high")
    assert fake.requests[-2]["form"]["query"].endswith("(severity eq 'high')")


async def test_policy_and_nat_match(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "policy_match", device="fw-edge", source="10.0.0.5", destination="8.8.8.8", destination_port=443,
                     from_zone="trust", to_zone="untrust", application="ssl")
    assert out["matched"] and out["first_match"]["name"] == "Allow web" and len(out["all_matches"]) == 2
    assert out["summary"] == "first match: rule 'Allow web' action allow"
    assert "<from>trust</from><to>untrust</to><source>10.0.0.5</source>" in fake.cmds()[-1]
    fake.override("<test><security-policy-match>", POLMATCH_NONE)
    out = await call(mcp, "policy_match", device="fw-edge", source="10.0.0.5", destination="8.8.8.8", destination_port=443)
    assert out["matched"] is False and "no explicit rule" in out["summary"]
    n = len(fake.requests)
    for bad in ({"source": "10.0.0.0/24"}, {"destination_port": None}, {"protocol": "gre-ish"}, {"from_zone": "t</from><set>"}):
        with pytest.raises(Exception):
            await mcp.call_tool("policy_match", {"device": "fw-edge", "source": "10.0.0.5", "destination": "8.8.8.8",
                                                 "destination_port": 443, **bad})
    with pytest.raises(Exception, match="only works on a firewall"):
        await mcp.call_tool("policy_match", {"device": "pan1", "source": "10.0.0.5", "destination": "8.8.8.8", "destination_port": 443})
    assert len(fake.requests) == n
    out = await call(mcp, "nat_match", device="fw-edge", source="10.0.0.5", destination="8.8.8.8", from_zone="trust",
                     to_zone="untrust", destination_port=443)
    assert out["matched"] and out["first_match"]["name"] == "Outbound PAT"


async def test_list_rules(inv, env):
    mcp, fake = mk(inv)
    out = await call(mcp, "list_rules", device="fw-edge")
    assert out["rules_in_rulebase"] == 3 and out["rules"][0]["name"] == "Allow web"
    assert out["rules"][0]["application"] == ["ssl", "web-browsing"] and out["rules"][0]["from"] == ["trust"]
    assert [r["name"] for r in (await call(mcp, "list_rules", device="fw-edge", action="deny"))["rules"]] == ["Block bad"]
    assert [r["name"] for r in (await call(mcp, "list_rules", device="fw-edge", application="ssl"))["rules"]] == [
        "Allow web", "Block bad", "Old rule"]                                              # 'any' rules also allow ssl
    assert [r["name"] for r in (await call(mcp, "list_rules", device="fw-edge", address_contains="bad-"))["rules"]] == ["Block bad"]
    assert (await call(mcp, "list_rules", device="fw-edge", rule_type="nat"))["rules_in_rulebase"] == 0
    with pytest.raises(Exception, match="device_group"):
        await mcp.call_tool("list_rules", {"device": "pan1"})
    await call(mcp, "list_rules", device="pan1", device_group="Branch", rulebase="post")
    assert "post-rulebase/security/rules" in fake.cmds()[-1] and "entry[@name='Branch']" in fake.cmds()[-1]
    for bad in ({"rule_type": "qos"}, {"rulebase": "middle"}, {"device_group": "x']|//*['"}):
        with pytest.raises(Exception):
            await mcp.call_tool("list_rules", {"device": "pan1", "device_group": "Branch", **bad})


async def test_config_sections_redact_by_default_and_can_be_unredacted(inv, env, monkeypatch):
    mcp, _ = mk(inv)
    out = await call(mcp, "get_config_section", device="fw-edge", section="address_objects")
    assert out["entries_found"] == 3 and [e["name"] for e in out["entries"]] == ["web1", "web2", "db1"] and out["redacted"] is True
    assert [e["name"] for e in (await call(mcp, "get_config_section", device="fw-edge", section="address_objects",
                                           name_contains="web"))["entries"]] == ["web1", "web2"]
    raw = (await mcp.call_tool("get_config_section", {"device": "fw-edge", "section": "system_settings"}))[0].text
    assert "Pu8l1cC0mm" not in raw and "REDACTED" in raw and "192.0.2.53" in raw
    monkeypatch.setenv("CONFIG_REDACT", "false")
    raw = (await mcp.call_tool("get_config_section", {"device": "fw-edge", "section": "system_settings"}))[0].text
    assert "Pu8l1cC0mm" in raw and json.loads(raw)["redacted"] is False
    for bad in ({"section": "nope"}, {"section": "device_groups"}, {"section": "pre_security_rules"},
                {"section": "zones", "vsys": "vsys1']/.."}):
        with pytest.raises(Exception):
            await mcp.call_tool("get_config_section", {"device": "fw-edge", **bad})
    out = await call(mcp, "get_config_section", device="pan1", section="device_groups")
    assert out["section"] == "device_groups" and "Branch" in json.dumps(out)


async def test_full_config_is_redacted_by_default_and_paged(inv, env, monkeypatch):
    mcp, fake = mk(inv)
    raw = (await mcp.call_tool("get_config", {"device": "fw-edge"}))[0].text
    out = json.loads(raw)
    assert out["redacted"] is True and out["redactions"] >= 3 and out["mode"] == "lines"
    for secret in SECRETS:
        assert secret not in raw
    assert any("<hostname>fw-edge</hostname>" in ln for ln in out["lines"])
    assert fake.requests[0]["form"] == {"type": "export", "category": "configuration"}
    out = await call(mcp, "get_config", device="fw-edge", search="ntp-server", context=1)
    assert out["mode"] == "search" and out["matches"] >= 1
    out = await call(mcp, "get_config", device="fw-edge", offset=2, limit=3)
    assert len(out["lines"]) == 3 and out["lines"][0].startswith("3: ") and "offset=5" in out["truncated"]
    monkeypatch.setenv("CONFIG_REDACT", "false")
    raw = (await mcp.call_tool("get_config", {"device": "fw-edge"}))[0].text
    assert "secrethashvalue" in raw and "unfiltered" in raw
    for bad in ({"limit": 0}, {"limit": 4001}, {"context": 9}, {"offset": -1}, {"search": "a;b"}):
        with pytest.raises(Exception):
            await mcp.call_tool("get_config", {"device": "fw-edge", **bad})


async def test_unknown_devices_and_ips_are_rejected_before_any_request(inv, env):
    mcp, fake = mk(inv)
    for tool in ("get_system_info", "get_ha_status", "get_licenses", "get_interfaces", "get_routes", "get_config"):
        for dev in ("198.51.100.9", "nope", "fw-edge; x"):
            with pytest.raises(Exception):
                await mcp.call_tool(tool, {"device": dev})
    assert fake.requests == []


async def test_login_with_username_and_password_instead_of_a_key(inv, monkeypatch):
    for k in ("PANOS_KEY_PANORAMA", "PANOS_KEY_FIREWALL", "PANOS_KEY_EDGE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PANOS_USER_EDGE", "readonly")
    monkeypatch.setenv("PANOS_PASS_EDGE", "S3cretPw")
    fake = Fake()
    inner = fake.__call__
    state = {"logins": 0, "expire": False}

    def handler(request):
        form = dict(parse_qsl(request.content.decode()))
        if form.get("type") == "keygen":
            assert form["user"] == "readonly" and "S3cretPw" not in str(request.url) and not request.url.query
            state["logins"] += 1
            return httpx.Response(200, text=wrap(f"<key>generated-key-{state['logins']}</key>"))
        if state["expire"] and request.headers.get("x-pan-key") == "generated-key-1":
            return httpx.Response(403, text="forbidden")
        return inner(request)

    mcp = build_server(inv, PanosClient(inv, transport=httpx.MockTransport(handler)), Audit(None))
    await call(mcp, "get_system_info", device="fw-edge")
    await call(mcp, "get_system_info", device="fw-edge")
    assert state["logins"] == 1                                              # key reused
    assert all(r["key"] == "generated-key-1" for r in fake.requests)
    state["expire"] = True
    await call(mcp, "get_system_info", device="fw-edge")                     # rejected once -> logs in again
    assert state["logins"] == 2 and fake.requests[-1]["key"] == "generated-key-2"
    with pytest.raises(Exception, match="no credentials are configured"):    # the managed firewall's Panorama has none
        await mcp.call_tool("get_system_info", {"device": "fw-managed"})


async def test_refused_login_does_not_leak_the_password(inv, monkeypatch):
    monkeypatch.setenv("PANOS_USER_EDGE", "readonly")
    monkeypatch.setenv("PANOS_PASS_EDGE", "S3cretPw")
    monkeypatch.delenv("PANOS_KEY_EDGE", raising=False)
    h = lambda r: httpx.Response(403, text='<response status="error" code="403"><result><msg>Invalid credentials. S3cretPw</msg></result></response>')
    mcp = build_server(inv, PanosClient(inv, transport=httpx.MockTransport(h)), Audit(None))
    with pytest.raises(Exception) as e:
        await mcp.call_tool("get_system_info", {"device": "fw-edge"})
    assert "S3cretPw" not in str(e.value) and "refused" in str(e.value)


async def test_config_on_one_line_with_big_blob_is_pretty_printed_clipped_and_capped(inv, env, monkeypatch):
    one_line = ('<config><shared><logo><content>' + "QUJD" * 5000 + '</content></logo></shared><mgt-config><users>'
                '<entry name="admin"><phash>$5$abc$secrethashvalue</phash></entry></users></mgt-config>'
                + "".join(f'<rule{i}><hostname>h{i}</hostname></rule{i}>' for i in range(3000)) + '</config>')

    class OneLine(Fake):
        def __call__(self, request):
            if dict(parse_qsl(request.content.decode())).get("type") == "export":
                return httpx.Response(200, text=one_line)
            return super().__call__(request)

    mcp, _ = mk(inv, OneLine())
    raw = (await mcp.call_tool("get_config", {"device": "fw-edge"}))[0].text
    out = json.loads(raw)
    assert out["total_lines"] > 3000 and len(out["lines"]) == 300 and "continue with offset=300" in out["truncated"]
    assert len(raw) < 31000 and "secrethashvalue" not in raw and "QUJDQUJD" not in raw
    out = await call(mcp, "get_config", device="fw-edge", search="logo")
    assert any("characters of data omitted" in ln or "<logo>" in ln for ln in out["lines"])
    out = await call(mcp, "get_config", device="fw-edge", search="phash")
    assert any("REDACTED" in ln for ln in out["lines"])
    out = await call(mcp, "get_config", device="fw-edge", limit=4000)                 # asking for more is still size-capped
    assert len(json.dumps(out)) < 32000 and "truncated" in out


async def test_refused_login_is_not_retried_straight_away(inv, monkeypatch):
    monkeypatch.setenv("PANOS_USER_EDGE", "readonly")
    monkeypatch.setenv("PANOS_PASS_EDGE", "wrong")
    monkeypatch.delenv("PANOS_KEY_EDGE", raising=False)
    attempts = []

    def h(request):
        attempts.append(1)
        return httpx.Response(403, text='<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>')

    mcp = build_server(inv, PanosClient(inv, transport=httpx.MockTransport(h)), Audit(None))
    for _ in range(3):
        with pytest.raises(Exception, match="refused"):
            await mcp.call_tool("get_system_info", {"device": "fw-edge"})
    assert len(attempts) == 1                                                # the other two calls did not touch the device
