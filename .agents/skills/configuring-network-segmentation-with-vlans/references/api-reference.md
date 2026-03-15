# API Reference: VLAN Network Segmentation Agent

## Overview

Configures and audits VLAN-based network segmentation on Cisco and multi-vendor switches using Netmiko and NAPALM. Creates VLANs, configures access/trunk ports, hardens unused ports, and audits for VLAN hopping vulnerabilities.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| netmiko | >=4.0 | SSH-based switch configuration |
| napalm | >=4.0 | Multi-vendor network device management |

## CLI Usage

```bash
# Audit VLAN configuration
python agent.py --host 192.168.1.1 --username admin --password pass --audit-only

# Full configuration mode
python agent.py --host 192.168.1.1 --username admin --password pass --device-type cisco_ios
```

## Key Functions

### `connect_netmiko(host, username, password, device_type)`
Establishes SSH connection via Netmiko supporting cisco_ios, cisco_nxos, arista_eos, juniper_junos.

### `get_vlan_config(conn)`
Retrieves current VLAN configuration with TextFSM parsing of `show vlan brief`.

### `create_vlan(conn, vlan_id, vlan_name)`
Creates a new VLAN with name on the switch.

### `configure_access_port(conn, interface, vlan_id)`
Configures port as access with port-security, portfast, and BPDU guard.

### `configure_trunk_port(conn, interface, allowed_vlans)`
Configures trunk port with explicit allowed VLANs, native VLAN 999, and DTP disabled.

### `harden_unused_ports(conn, interfaces)`
Assigns unused ports to quarantine VLAN 999 and shuts them down.

### `configure_inter_vlan_acl(conn, acl_name, rules)`
Creates extended ACLs for inter-VLAN routing access control.

### `audit_vlan_security(conn)`
Checks for: default native VLAN, unhardened unused ports, and DTP negotiation enabled.

### `get_napalm_config(host, username, password, driver)`
Retrieves device facts, interfaces, and VLANs using NAPALM for multi-vendor support.

## Security Checks

| Check | Severity | Issue |
|-------|----------|-------|
| Native VLAN | Medium | Default VLAN 1 on trunks enables VLAN hopping |
| Unused Ports | Low | Unhardened ports allow unauthorized network access |
| DTP Negotiation | High | Dynamic trunking enables VLAN hopping attacks |
| Port Security | Medium | Missing MAC address limiting |

## Supported Device Types

Netmiko: `cisco_ios`, `cisco_nxos`, `arista_eos`, `juniper_junos`, `hp_procurve`
NAPALM: `ios`, `nxos`, `eos`, `junos`
