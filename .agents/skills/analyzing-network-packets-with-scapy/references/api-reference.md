# Scapy Network Packet Analysis API Reference

## Core Scapy Functions

### Reading Packets
```python
from scapy.all import rdpcap, sniff, wrpcap

# Read pcap file
packets = rdpcap("capture.pcap")

# Live sniff with BPF filter (requires root)
packets = sniff(filter="tcp port 80", count=100, iface="eth0")

# Write packets to pcap
wrpcap("output.pcap", packets)
```

### Packet Layer Access
```python
from scapy.all import IP, TCP, UDP, DNS, DNSQR, ICMP

pkt = packets[0]
pkt.haslayer(IP)        # Check if layer exists
pkt[IP].src             # Source IP
pkt[IP].dst             # Destination IP
pkt[TCP].sport          # Source port
pkt[TCP].dport          # Destination port
pkt[TCP].flags          # TCP flags: S, SA, A, FA, R, PA
pkt[DNS].qd.qname       # DNS query name
pkt[ICMP].type          # ICMP type (8=echo request, 0=echo reply)
```

### Packet Crafting
```python
from scapy.all import IP, TCP, sr1, send

# SYN probe (authorized testing only)
syn = IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
response = sr1(syn, timeout=2, verbose=0)

# ICMP ping
ping = IP(dst="192.168.1.1") / ICMP()
send(ping, verbose=0)

# Custom DNS query
dns = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
```

## Protocol Fields Reference

### TCP Flags
| Flag | Value | Meaning |
|------|-------|---------|
| S | 0x02 | SYN |
| SA | 0x12 | SYN-ACK |
| A | 0x10 | ACK |
| F | 0x01 | FIN |
| R | 0x04 | RST |
| P | 0x08 | PSH |

### ICMP Types
| Type | Meaning |
|------|---------|
| 0 | Echo Reply |
| 3 | Destination Unreachable |
| 8 | Echo Request |
| 11 | Time Exceeded |

## BPF Filter Syntax
```
tcp port 443              # TCP traffic on port 443
host 10.0.0.1             # All traffic to/from IP
src net 192.168.0.0/24    # Source from subnet
udp and port 53           # DNS traffic
tcp[tcpflags] & tcp-syn != 0  # SYN packets only
```

## CLI Usage

```bash
# Analyze pcap file for anomalies
python agent.py --pcap capture.pcap --output report.json

# Custom thresholds
python agent.py --pcap traffic.pcapng --syn-threshold 50 --dns-length 30

# Port scan detection sensitivity
python agent.py --pcap scan.pcap --scan-threshold 10
```
