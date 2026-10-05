"""Read-only Palo Alto (PAN-OS / Panorama) MCP server (Streamable HTTP, loopback only).

Registers only read-only tools. There is deliberately no generic command or XML runner, no configuration change, no commit,
and no import: the API client can only send the fixed requests defined in app/commands.py."""
import functools
import logging
import os

from mcp.server.fastmcp import FastMCP

from app.adapters.panos import PanosClient
from app.audit import Audit
from app.tools import devices as dv
from app.tools import health as hl
from app.tools import logs as lg
from app.tools import network as nw
from app.tools import policy as pl
from app.validation import Inventory


def build_server(inv: Inventory, client: PanosClient, audit: Audit) -> FastMCP:
    host = os.environ.get("MCP_BIND_ADDRESS", "127.0.0.1")
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit("MCP_BIND_ADDRESS must be loopback")
    mcp = FastMCP("paloalto-network-readonly", host=host, port=int(os.environ.get("MCP_PORT", "8766")))

    def tagged(fn):
        """Label every result with the device kind and, for a managed firewall, the Panorama it was queried through."""
        @functools.wraps(fn)
        async def wrapper(**params):
            result = await fn(**params)
            d = inv.lookup(params.get("device") or params.get("panorama"))
            if isinstance(result, dict) and d:
                result = {"device": d.name, "kind": d.kind, "managed_by": d.via,
                          **{k: v for k, v in result.items() if k not in ("device", "panorama")}}
            return result
        return wrapper

    # ---------------- devices ----------------
    @mcp.tool()
    @audit.tool("list_devices", "inventory")
    async def list_devices(name_contains: str | None = None, site: str | None = None, kind: str | None = None,
                           limit: int = 50) -> dict:
        """List approved Palo Alto devices (Panorama and firewalls) with site, model and how they are reached. Filter with
        name_contains, site or kind (panorama, firewall); limit up to 200."""
        return await dv.list_devices(inv, name_contains, site, kind, limit)

    @mcp.tool()
    @audit.tool("list_panorama_devices", "panos-api")
    @tagged
    async def list_panorama_devices(panorama: str, connected_only: bool = True, limit: int = 100) -> dict:
        """List the firewalls a Panorama manages (serial, hostname, model, software, HA state, connected) and whether each
        is in the inventory. Use connected_only=false to include disconnected ones."""
        return await dv.list_panorama_devices(inv, client, panorama, connected_only, limit)

    # ---------------- health ----------------
    @mcp.tool()
    @audit.tool("get_system_info", "panos-api")
    @tagged
    async def get_system_info(device: str) -> dict:
        """Hostname, model, serial, software, content (app/threat/antivirus) versions, uptime and mode for a device."""
        return await hl.get_system_info(inv, client, device)

    @mcp.tool()
    @audit.tool("get_resources", "panos-api")
    @tagged
    async def get_resources(device: str) -> dict:
        """Management-plane CPU, memory and load average (the device's own 'show system resources')."""
        return await hl.get_resources(inv, client, device)

    @mcp.tool()
    @audit.tool("get_disk_space", "panos-api")
    @tagged
    async def get_disk_space(device: str) -> dict:
        """Filesystem usage; flags filesystems that are 90% or more full."""
        return await hl.get_disk_space(inv, client, device)

    @mcp.tool()
    @audit.tool("get_ha_status", "panos-api")
    @tagged
    async def get_ha_status(device: str) -> dict:
        """High-availability state: enabled, mode, local and peer state, configuration sync. Flags problems."""
        return await hl.get_ha_status(inv, client, device)

    @mcp.tool()
    @audit.tool("get_licenses", "panos-api")
    @tagged
    async def get_licenses(device: str) -> dict:
        """Installed licences with expiry dates and days left; flags expired ones and those expiring within 60 days."""
        return await hl.get_licenses(inv, client, device)

    @mcp.tool()
    @audit.tool("get_certificates", "panos-api")
    @tagged
    async def get_certificates(device: str) -> dict:
        """Shared certificates with expiry, soonest first; flags expired ones and those expiring within 60 days."""
        return await hl.get_certificates(inv, client, device)

    @mcp.tool()
    @audit.tool("get_jobs", "panos-api")
    @tagged
    async def get_jobs(device: str, limit: int = 20) -> dict:
        """Recent jobs (commits, installs, downloads) newest first, with their result; flags failed jobs."""
        return await hl.get_jobs(inv, client, device, limit)

    # ---------------- network ----------------
    @mcp.tool()
    @audit.tool("get_interfaces", "panos-api")
    @tagged
    async def get_interfaces(device: str, name_contains: str | None = None, limit: int = 100) -> dict:
        """Interfaces with link state, speed, zone, IP, virtual router and VLAN tag. Flags down interfaces that are in a zone."""
        return await nw.get_interfaces(inv, client, device, name_contains, limit)

    @mcp.tool()
    @audit.tool("get_interface_counters", "panos-api")
    @tagged
    async def get_interface_counters(device: str, name: str | None = None, only_errors: bool = False,
                                     limit: int = 50) -> dict:
        """Interface traffic and error/drop counters. Give name (e.g. 'ethernet1/1') for one interface, or only_errors=true
        to list just those with errors or drops. Counters are cumulative."""
        return await nw.get_interface_counters(inv, client, device, name, only_errors, limit)

    @mcp.tool()
    @audit.tool("get_drop_counters", "panos-api")
    @tagged
    async def get_drop_counters(device: str, delta: str = "yes", severity: str = "drop", limit: int = 40) -> dict:
        """Global packet-drop counters (why packets are discarded), highest first. delta=yes shows the change since the last
        reading, delta=no shows totals since boot. severity: drop, error, warn or info."""
        return await nw.get_drop_counters(inv, client, device, delta, severity, limit)

    @mcp.tool()
    @audit.tool("get_routes", "panos-api")
    @tagged
    async def get_routes(device: str, virtual_router: str | None = None, destination_contains: str | None = None,
                         limit: int = 100) -> dict:
        """The routing table (destination, next hop, interface, metric, flags), with the default routes listed separately.
        Filter by virtual_router or part of a destination."""
        return await nw.get_routes(inv, client, device, virtual_router, destination_contains, limit)

    @mcp.tool()
    @audit.tool("lookup_route", "panos-api")
    @tagged
    async def lookup_route(device: str, destination: str, virtual_router: str | None = None) -> dict:
        """Which interface and next hop the firewall would use to reach an IPv4 address (its own forwarding lookup). Without virtual_router every virtual router is asked."""
        return await nw.lookup_route(inv, client, device, destination, virtual_router)

    @mcp.tool()
    @audit.tool("get_session_info", "panos-api")
    @tagged
    async def get_session_info(device: str) -> dict:
        """Session table usage (active and maximum sessions, protocol mix, packet and connection rates). Flags 80%+ full."""
        return await nw.get_session_info(inv, client, device)

    @mcp.tool()
    @audit.tool("find_sessions", "panos-api")
    @tagged
    async def find_sessions(device: str, source: str | None = None, destination: str | None = None,
                            destination_port: int | None = None, source_port: int | None = None,
                            application: str | None = None, protocol: str | None = None, from_zone: str | None = None,
                            to_zone: str | None = None, rule: str | None = None, state: str | None = None,
                            limit: int = 25) -> dict:
        """Search active sessions. At least one filter is required: source or destination (IP or network),
        destination_port, source_port, application, protocol (tcp, udp, icmp or a number), from_zone, to_zone, rule,
        state (active, closed, discard, init, opening). limit up to 200."""
        return await nw.find_sessions(inv, client, device, source, destination, destination_port, source_port,
                                      application, protocol, from_zone, to_zone, rule, state, limit)

    @mcp.tool()
    @audit.tool("get_vpn_status", "panos-api")
    @tagged
    async def get_vpn_status(device: str, limit: int = 50) -> dict:
        """IKE gateway and IPsec tunnel state; flags tunnels that are down or initialising."""
        return await nw.get_vpn_status(inv, client, device, limit)

    @mcp.tool()
    @audit.tool("get_globalprotect_users", "panos-api")
    @tagged
    async def get_globalprotect_users(device: str, limit: int = 50) -> dict:
        """Users currently connected to the GlobalProtect gateway (username, addresses, client, login time)."""
        return await nw.get_globalprotect_users(inv, client, device, limit)

    # ---------------- logs ----------------
    @mcp.tool()
    @audit.tool("search_logs", "panos-api")
    @tagged
    async def search_logs(device: str, log_type: str = "traffic", window: str = "1h", source: str | None = None,
                          destination: str | None = None, application: str | None = None, action: str | None = None,
                          rule: str | None = None, destination_port: int | None = None, from_zone: str | None = None,
                          to_zone: str | None = None, severity: str | None = None, limit: int = 50) -> dict:
        """Search logs with structured filters. log_type: traffic, threat, url, wildfire, system, config, globalprotect,
        userid, auth. window: 15m, 1h, 6h, 24h, 7d. Filters: source, destination (IP or network), application, action
        (allow, deny, drop, reset-client, reset-server, reset-both, alert, block-ip, block-url), rule, destination_port,
        from_zone, to_zone, severity (informational, low, medium, high, critical). limit up to 200, newest first."""
        return await lg.search_logs(inv, client, device, log_type, window, source, destination, application, action, rule,
                                    destination_port, from_zone, to_zone, severity, limit)

    # ---------------- policy and configuration ----------------
    @mcp.tool()
    @audit.tool("policy_match", "panos-api")
    @tagged
    async def policy_match(device: str, source: str, destination: str, protocol: str = "tcp",
                           destination_port: int | None = None, from_zone: str | None = None,
                           to_zone: str | None = None, application: str | None = None) -> dict:
        """Which security rule would match this traffic: the firewall's own policy-match test. source and destination are
        IPv4 addresses; destination_port is required for tcp and udp; from_zone and to_zone and application are optional.
        Firewalls only."""
        return await pl.policy_match(inv, client, device, source, destination, protocol, destination_port, from_zone,
                                     to_zone, application)

    @mcp.tool()
    @audit.tool("nat_match", "panos-api")
    @tagged
    async def nat_match(device: str, source: str, destination: str, from_zone: str, to_zone: str, protocol: str = "tcp",
                        destination_port: int | None = None, source_port: int | None = None) -> dict:
        """Which NAT rule would match this traffic: the firewall's own nat-policy-match test. Firewalls only."""
        return await pl.nat_match(inv, client, device, source, destination, from_zone, to_zone, protocol,
                                  destination_port, source_port)

    @mcp.tool()
    @audit.tool("list_rules", "panos-api")
    @tagged
    async def list_rules(device: str, rule_type: str = "security", name_contains: str | None = None,
                         application: str | None = None, action: str | None = None, address_contains: str | None = None,
                         device_group: str | None = None, rulebase: str = "pre", limit: int = 100) -> dict:
        """List security or NAT rules in evaluation order (name, zones, addresses, applications, services, action).
        Filter by name_contains, application, action or address_contains. For a Panorama give device_group and rulebase
        (pre or post)."""
        return await pl.list_rules(inv, client, device, rule_type, name_contains, application, action, address_contains,
                                   device_group, rulebase, limit)

    @mcp.tool()
    @audit.tool("get_config_section", "panos-api")
    @tagged
    async def get_config_section(device: str, section: str, name_contains: str | None = None,
                                 device_group: str | None = None, vsys: str | None = None, limit: int = 100) -> dict:
        """Read one part of the configuration. section: security_rules, nat_rules, address_objects, address_groups, services,
        service_groups, zones, interfaces, virtual_routers, ha, system_settings, certificates; Panorama only: device_groups,
        templates, pre_security_rules, post_security_rules, pre_nat_rules, post_nat_rules (the last four need device_group).
        Secrets are redacted unless the server is configured otherwise."""
        return await pl.get_config_section(inv, client, device, section, name_contains, device_group, vsys, limit)

    @mcp.tool()
    @audit.tool("get_config", "panos-api")
    @tagged
    async def get_config(device: str, search: str | None = None, context: int = 2, offset: int | None = None,
                         limit: int = 300) -> dict:
        """The running configuration as numbered XML lines. Use search (text) to find lines with context around them, or
        offset+limit to page through it (default 300 lines, up to 4000; replies are also capped in size). Secrets are redacted unless the server is configured otherwise."""
        return await pl.get_config(inv, client, device, search, context, offset, limit)

    return mcp


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    inv = Inventory.load(os.environ.get("INVENTORY_FILE", "/etc/paloalto-mcp/inventory.yaml"))
    build_server(inv, PanosClient(inv), Audit(os.environ.get("AUDIT_LOG"))).run(transport="streamable-http")


if __name__ == "__main__":
    main()
