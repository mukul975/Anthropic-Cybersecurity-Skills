# API Reference: IPv6 Vulnerability Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| scapy | >=2.5 | IPv6 packet crafting, NDP analysis, RA capture |

## CLI Usage

```bash
sudo python scripts/agent.py \
  --interface eth0 \
  --known-routers "fe80::1" "fe80::2" \
  --output ipv6_report.json
```

## Functions

### `discover_ipv6_hosts(interface, timeout) -> list`
Sends ICMPv6 Echo Request to `ff02::1` (all-nodes multicast) and collects replies.

### `capture_router_advertisements(interface, timeout) -> list`
Sniffs ICMPv6 type 134 (Router Advertisements) and extracts prefix info, DNS servers, and flags.

### `detect_rogue_ra(ras, known_routers) -> list`
Compares RA source addresses against a known-router allowlist. Unrecognized sources flagged as rogue.

### `check_ipv6_firewall() -> dict`
Runs `ip6tables -L -n` to check for IPv6 firewall rules. Empty ruleset is flagged.

### `check_tunnel_protocols(interface, timeout) -> dict`
Sniffs for Teredo (UDP 3544), 6to4 (IP proto 41), and ISATAP tunnel traffic.

### `generate_assessment(interface, known_routers) -> dict`
Orchestrates all checks and produces the final assessment report.

## Scapy Layers Used

| Layer | Purpose |
|-------|---------|
| `ICMPv6ND_RA` | Router Advertisement parsing |
| `ICMPv6NDOptPrefixInfo` | Prefix information extraction |
| `ICMPv6NDOptRDNSS` | DNS server option extraction |
| `ICMPv6EchoRequest` | Multicast host discovery |

## Output Schema

```json
{
  "interface": "eth0",
  "ipv6_hosts_discovered": 15,
  "router_advertisements": [{"src_ip": "fe80::1", "router_lifetime": 1800}],
  "rogue_ras": [],
  "firewall_status": {"rules_count": 0},
  "tunnel_protocols": {"teredo": false},
  "risk_findings": ["HIGH: No ip6tables rules configured"]
}
```
