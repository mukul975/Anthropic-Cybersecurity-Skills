# API Reference: pfSense Firewall Configuration Agent

## Overview

Manages pfSense firewall rules via the REST API: creates LAN/DMZ/Guest isolation rules, configures NAT port forwarding, and audits rules for overly permissive or undocumented entries.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | pfSense REST API communication |

## Prerequisites

- pfSense 2.7+ with the `pfsense-api` package installed
- API key and secret configured in pfSense WebConfigurator

## CLI Usage

```bash
# Audit existing rules
python agent.py --url https://192.168.1.1 --api-key <key> --api-secret <secret> --audit-only

# Create DMZ and Guest isolation rules
python agent.py --url https://192.168.1.1 --api-key <key> --api-secret <secret> \
  --setup-dmz --setup-guest
```

## Key Functions

### `PfSenseAPI(base_url, api_key, api_secret)`
REST API client for pfSense with GET, POST, PUT, DELETE methods.

### `get_firewall_rules(api)`
Retrieves all configured firewall rules from pfSense.

### `create_firewall_rule(api, interface, action, protocol, source, destination, dst_port, description)`
Creates a new firewall rule on the specified interface.

### `create_lan_to_wan_rules(api)`
Creates standard LAN egress rules: HTTP, HTTPS, DNS allowed; all else blocked.

### `create_dmz_rules(api, dmz_interface)`
Creates DMZ isolation rules: inbound web traffic allowed, DMZ-to-LAN blocked.

### `create_guest_isolation_rules(api, guest_interface)`
Blocks guest network from all RFC1918 ranges, allows internet-only access.

### `configure_nat_port_forward(api, interface, external_port, target_ip, target_port)`
Creates NAT port forwarding rules for inbound service access.

### `audit_firewall_rules(rules)`
Audits for: any-to-any pass rules, undocumented rules, and disabled rules.

## pfSense API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/firewall/rule` | GET | List all rules |
| `/api/v1/firewall/rule` | POST | Create new rule |
| `/api/v1/firewall/nat/port_forward` | POST | Create NAT rule |
| `/api/v1/diagnostics/system_log/firewall` | GET | Retrieve firewall logs |

## Rule Templates

| Template | Rules | Purpose |
|----------|-------|---------|
| LAN-to-WAN | 5 | Standard egress (HTTP, HTTPS, DNS + block all) |
| DMZ | 6 | Web inbound, block to LAN, limited outbound |
| Guest | 6 | Block RFC1918, allow internet only |
