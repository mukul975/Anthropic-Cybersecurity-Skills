# API Reference: VLAN Hopping Attack Agent

## Overview

Tests VLAN segmentation effectiveness using scapy for DTP switch spoofing and 802.1Q double-tagging attacks in authorized penetration testing environments.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| scapy | >= 2.5 | Packet crafting for DTP and Dot1Q frames |
| subprocess | stdlib | Interface management and modprobe |

## Core Functions

### `listen_for_dtp(iface, timeout)`
Sniffs for DTP frames on the interface to detect trunk negotiation capability.
- **Returns**: `dict` with `dtp_frames_received`, `dtp_active`, `details`

### `listen_for_cdp_lldp(iface, timeout)`
Captures CDP and LLDP discovery frames to identify the connected switch.
- **Returns**: `dict` with `frames` and `switch_discovered`

### `send_dtp_desirable(iface, count)`
Sends DTP desirable frames to negotiate a trunk link on an access port.
- **Protocol**: DTP multicast to `01:00:0c:cc:cc:cc`
- **Returns**: `dict` with `frames_sent`, `type`

### `create_vlan_interface(iface, vlan_id, ip_addr)`
Creates 802.1Q VLAN subinterface after successful trunk negotiation.
- **Requires**: `8021q` kernel module
- **Returns**: `dict` with `vlan_interface`, `vlan_id`, `ip`

### `send_double_tagged(iface, outer_vlan, inner_vlan, target_ip)`
Crafts and sends double-tagged 802.1Q frames for VLAN hopping.
- **Note**: Unidirectional attack - no return traffic expected
- **Returns**: `dict` with VLAN IDs and target

### `cleanup_vlan_interfaces(iface, vlan_ids)`
Removes VLAN subinterfaces created during testing.

### `run_assessment(iface, target_vlans, target_ips)`
Full assessment: DTP listening, switch spoofing, double tagging, cleanup.

## Scapy Layers Used

| Layer | Purpose |
|-------|---------|
| `Ether` | Ethernet frame construction |
| `Dot1Q` | 802.1Q VLAN tagging (single and double) |
| `LLC/SNAP` | DTP frame encapsulation |
| `IP/ICMP` | Test payload for VLAN reachability |

## Requirements

- Root/sudo privileges for raw packet operations
- Monitor mode or promiscuous mode capable interface
- Authorization for target network testing

## Usage

```bash
sudo python agent.py eth0
```
