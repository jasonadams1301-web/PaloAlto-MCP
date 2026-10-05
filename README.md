# paloalto-mcp

A **read-only** [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that lets an AI agent inspect
Palo Alto Networks **Panorama** and **PAN-OS firewalls** for monitoring and troubleshooting, built for
[OpenClaw Enterprise](https://github.com/mholovetskyi/openclawenterprise) (OCE) on Ubuntu Server. It follows the same design as
the sibling `extreme-mcp` project.

It can look. It cannot change anything.

- Talks to the **PAN-OS XML API** over HTTPS, either to a Panorama (which can proxy to the firewalls it manages) or to a firewall directly.
- Runs as its own systemd service on the OCE host, bound to **127.0.0.1 only**.
- Credentials never leave the service. The agent receives results, not passwords.

## Tools (24)

| Group | Tool | What it returns |
|---|---|---|
| Inventory | `list_devices` | Approved devices (Panorama / firewalls), filter by name, site or kind |
| | `list_panorama_devices` | The firewalls a Panorama reports as managed, connection state, and which ones are not in the inventory |
| Health | `get_system_info` | Hostname, model, serial, PAN-OS and content versions, uptime |
| | `get_resources` | Management CPU, memory and load |
| | `get_disk_space` | Filesystem usage; flags nearly full partitions |
| | `get_ha_status` | HA enabled, local/peer state, config sync; flags problems |
| | `get_licenses` | Licences with days left; flags expired or expiring |
| | `get_certificates` | Device certificates, soonest expiry first; flags expired or expiring |
| | `get_jobs` | Recent jobs (commits, downloads), flags failures |
| Network | `get_interfaces` | Interfaces with state, zone, IP, speed; flags down interfaces that are in a zone |
| | `get_interface_counters` | Per-interface counters; `only_errors` shows just errors and drops |
| | `get_drop_counters` | Global drop counters (non-zero only), the quickest "why is traffic being dropped" view |
| | `get_routes` | Routing table, default routes, filter by virtual router or destination |
| | `lookup_route` | The route the firewall would use for a destination (FIB lookup) |
| | `get_session_info` | Session table utilisation and rates |
| | `find_sessions` | Matching sessions (a filter is required) |
| | `get_vpn_status` | IKE gateways and IPsec tunnels; flags non-up |
| | `get_globalprotect_users` | Connected GlobalProtect users |
| Logs | `search_logs` | Traffic, threat, system, config, URL, ... logs by time window and validated filters (source, destination, application, rule, action, severity) |
| Policy | `policy_match` | The firewall's own security-policy-match test: which rule would a flow hit |
| | `nat_match` | The firewall's own NAT-policy-match test |
| | `list_rules` | Security or NAT rules (Panorama: per device group, pre or post) with filters |
| | `get_config_section` | A fixed section of the configuration (addresses, services, zones, system settings, ...) |
| | `get_config` | The running configuration, paged or searched |

## Security model

The point is that a prompt-injected or confused agent **cannot** do harm through this server.

- **No write path exists.** Operational commands come from a fixed table that contains only `show` and `test` commands (plus
  `request license info`, which is read-only). Import-time assertions fail if anything else is added. There is no generic
  command runner, no commit, no `set`/`edit`/`delete`, no config load.
- **Callers never supply XML or XPath.** Each tool maps to a fixed command or XPath; variable parts (IP, port, zone, rule, application,
  interface, vsys, device group) are validated with strict patterns and then placed into the XML as escaped text.
- **Inventory allowlist.** Every call names a device in the inventory. IPs and arbitrary hostnames are rejected before any request.
- **Use a read-only account.** Create a dedicated admin role (XML API: operational requests, configuration read, logs and export
  allowed; commit, import and everything else off) and an account with it. The server logs in with that username and password
  (keygen) and keeps the session key in memory only; a pre-generated API key also works. Even if the software were bypassed,
  the device enforces read-only.
- **TLS:** by default each device's own certificate is **pinned** (`certs/<name>.pem`, approved by you after checking the fingerprint),
  since management interfaces usually use self-signed certificates. `tls: ca` uses normal CA verification instead.
- **Loopback only**, secrets as systemd credentials, per-call JSON audit log, hardened systemd unit.
- **Treat device text as data.** Log entries and object names come from the network and can contain attacker-influenced text.

### Configuration redaction

Firewall configurations contain password hashes, pre-shared keys, SNMP communities and RADIUS/TACACS secrets. Unlike the
switch project, `get_config` and `get_config_section` therefore **redact by default**: values of elements whose names mean
secret (password, phash, secret, community, psk, key, token, ...) and PEM blocks are replaced with `REDACTED`. It is best-effort
(a secret under an unexpected element name could be missed), so the output is still sensitive. Set `CONFIG_REDACT=false`
in `/etc/paloalto-mcp/paloalto-mcp.env` to return configuration unfiltered for administrators.

## Inventory

`/etc/paloalto-mcp/inventory.yaml` (server only; see `inventory.example.yaml`). Entries need `mcp_enabled: true`.

- `kind: panorama` with `address`.
- `kind: firewall` with `via: <panorama name>` and `serial` (queried through the Panorama with `target=<serial>`; uses the Panorama's key and certificate), or with `address` (queried directly).
- Optional: `site`, `model`, `credential` (use key `panos_key_<credential>`), `tls` (`pinned` or `ca`), `vsys`.

Credentials are `panos_user_<name>` + `panos_pass_<name>` (or `panos_key_<name>`), where `<name>` is `panorama`, `firewall` or the entry's `credential`. Keep the real inventory out of git.

## Adding the firewalls a Panorama manages

`import-panorama.py` is an administrator tool (not an MCP tool, so an agent cannot change the device list). It reads the firewalls
a Panorama manages and adds them to the inventory as **direct** connections, pinning each device certificate. It runs as root
on the server, because it uses the stored Panorama login and writes to `/etc/paloalto-mcp`.

```
sudo /opt/paloalto-mcp/venv/bin/python /opt/paloalto-mcp/import-panorama.py <panorama name>
```

1. **Review** (writes nothing): for every firewall it prints name, management IP, model, certificate subject, SHA256 fingerprint,
   expiry and issuer, and whether pinning will work. Devices with an expired or CA-only certificate, or that cannot be reached,
   are listed with the reason and are not added. It ends with a review code.
2. **Write**: `... --write --confirm <review code>` scans again and applies only if every certificate still matches what was
   reviewed. It appends the entries (existing ones and comments are untouched), writes `certs/<name>.pem`, keeps a timestamped
   backup of the inventory, checks the result loads, and rolls everything back on failure. Then restart the service.

**Refreshing pins.** Factory certificates expire, and a pin matches one exact certificate, so run
`import-panorama.py --refresh` now and then (no Panorama needed). It re-checks every pinned firewall, lists those whose
certificate changed (old and new fingerprint, expiry, common name) and any that expire within 90 days, and ends with a review
code. `--refresh --write --confirm <code>` re-pins only what you reviewed and keeps the old file as `<name>.pem.bak-<time>`.
Restart the service afterwards.

Firewalls already in the inventory (same serial or address) are skipped. Options: `--all` (include disconnected firewalls),
`--only TEXT`. Direct connections use the shared read-only login `panos_user_firewall` / `panos_pass_firewall`.

## Deploy

```
bash install.sh                                   # user, dirs, venv, code, unit
vi /etc/paloalto-mcp/inventory.yaml
bash set-secret.sh panos_user_firewall            # prompts without echo; then panos_pass_firewall (or *_panorama)
/opt/paloalto-mcp/venv/bin/python /opt/paloalto-mcp/scan-cert.py panorama.example.net | sudo tee /etc/paloalto-mcp/certs/pan-primary.pem
sudo systemctl enable --now paloalto-mcp && sudo ss -lntp | grep ':8766'     # must show 127.0.0.1
```

Compare the fingerprint `scan-cert.py` prints with the one on the device before saving the certificate.

Register in OCE:

```
openclaw mcp add paloalto-network-readonly --transport streamable-http --url http://127.0.0.1:8766/mcp
openclaw mcp tools paloalto-network-readonly
```

With a small local model, give the firewall tools to a separate agent (or use `--include`) rather than one agent with every network tool.

## Configuration

| Variable | Default | |
|---|---|---|
| `MCP_BIND_ADDRESS` / `MCP_PORT` | 127.0.0.1 / 8766 | loopback only |
| `INVENTORY_FILE` | /etc/paloalto-mcp/inventory.yaml | |
| `AUDIT_LOG` | | JSON line per call |
| `PANOS_CERT_DIR` | /etc/paloalto-mcp/certs | pinned certificates |
| `PANOS_CA_BUNDLE` | system | for `tls: ca` |
| `PANOS_TIMEOUT_SECONDS` / `PANOS_MAX_PARALLEL` | 30 / 6 | |
| `CONFIG_REDACT` | true | see above |

## Development

```
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

**Tested on real devices:** a full Panorama (with its managed firewalls and device groups), and PA-440, PA-850 and PA-3220 firewalls,
all running a supported PAN-OS release. Response layouts for some commands vary by PAN-OS version and model, so parsers are
tolerant, and each tool reports `parse_warnings` with the raw result when it cannot recognise a response. Verify against your own
devices after deploying.

## Licence

See `LICENSE`.
