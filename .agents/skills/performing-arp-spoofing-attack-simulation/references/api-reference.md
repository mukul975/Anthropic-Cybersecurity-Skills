# API Reference: Performing ARP Spoofing Attack Simulation

## Scapy Library (Core)

| Function/Class | Description |
|----------------|-------------|
| `ARP(op="is-at", psrc=ip, hwsrc=mac)` | Construct ARP reply (poison) packet |
| `Ether(dst=mac)` | Construct Ethernet frame with target MAC |
| `srp(packet, timeout, iface)` | Send and receive layer 2 packets (ARP resolution) |
| `sendp(packet, iface)` | Send packet at layer 2 without waiting for reply |
| `get_if_hwaddr(iface)` | Get MAC address of local interface |
| `get_if_list()` | List available network interfaces |
| `conf.iface` | Get/set default network interface |

## ARP Packet Fields

| Field | Description |
|-------|-------------|
| `op` | Operation: `"who-has"` (request) or `"is-at"` (reply) |
| `psrc` | Source protocol (IP) address |
| `pdst` | Destination protocol (IP) address |
| `hwsrc` | Source hardware (MAC) address |
| `hwdst` | Destination hardware (MAC) address |

## Detection Verification Commands

| Command | Platform | Description |
|---------|----------|-------------|
| `show ip arp inspection statistics` | Cisco IOS | DAI statistics and violations |
| `show ip arp inspection log` | Cisco IOS | DAI violation log entries |
| `arpwatch -i eth0` | Linux | Monitor ARP table changes |
| `ip neigh show` | Linux | Display current ARP cache |

## Key Libraries

- **scapy** (`pip install scapy`): Packet crafting and network interaction
- **netifaces**: Cross-platform network interface information
- **nmap** (python-nmap): Network host discovery as alternative to ARP scan

## Configuration

| Variable | Description |
|----------|-------------|
| Interface | Network interface on same VLAN as target (e.g., `eth0`) |
| Root/Admin | Scapy requires root/administrator privileges for raw sockets |

## Safety Controls

| Control | Purpose |
|---------|---------|
| Written authorization | Legal requirement before any ARP spoofing |
| `restore_arp()` | Always restore legitimate ARP entries after simulation |
| Packet count limit | Limit spoofing rounds to minimum needed for detection test |
| Isolated VLAN | Run simulation on isolated test network segment |

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Dynamic ARP Inspection (Cisco)](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/16-12/configuration_guide/sec/b_1612_sec_9300_cg/dynamic_arp_inspection.html)
- [OWASP Testing Guide - Network](https://owasp.org/www-project-web-security-testing-guide/)
