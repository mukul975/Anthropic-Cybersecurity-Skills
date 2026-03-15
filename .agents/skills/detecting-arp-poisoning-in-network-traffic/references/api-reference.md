# ARP Poisoning Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| scapy | `pip install scapy` | PCAP parsing and ARP packet analysis |

## Scapy ARP Packet Fields

| Field | Description |
|-------|-------------|
| `op` | Operation: 1=request, 2=reply |
| `hwsrc` | Source MAC address |
| `psrc` | Source IP address |
| `hwdst` | Destination MAC address |
| `pdst` | Destination IP address |

## ARP Spoofing Indicators

| Indicator | Description | Severity |
|-----------|-------------|----------|
| Duplicate MACs for IP | Same IP mapped to multiple MACs | CRITICAL |
| MAC claiming many IPs | One MAC responding for 3+ IPs | HIGH |
| Gratuitous ARP flood | Excessive unsolicited ARP replies | MEDIUM |
| ARP flip-flop | IP/MAC mapping changes rapidly | HIGH |

## Scapy PCAP Analysis

```python
from scapy.all import rdpcap, ARP
packets = rdpcap("capture.pcap")
arp_replies = [p for p in packets if ARP in p and p[ARP].op == 2]
```

## System ARP Table

```bash
arp -a                  # Display ARP table
arp -d <ip>            # Delete ARP entry
ip neigh show          # Linux: show neighbor table
```

## arpwatch Database Format

```
<mac>\t<ip>\t<timestamp>\t<hostname>
```

## Detection Tools

| Tool | Description |
|------|-------------|
| arpwatch | Monitors ARP table changes, emails on flip-flop |
| arpsnitch | Real-time ARP spoofing alert |
| XArp | Advanced ARP spoofing detection |
| Snort rule | `alert arp any any -> any any (msg:"ARP spoof"; ...)` |

## External References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [arpwatch Manual](https://linux.die.net/man/8/arpwatch)
- [MITRE T1557.002 — ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/)
