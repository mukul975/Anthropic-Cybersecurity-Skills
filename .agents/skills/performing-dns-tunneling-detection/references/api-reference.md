# API Reference: Performing DNS Tunneling Detection

## scapy (DNS Packet Analysis)

```python
from scapy.all import rdpcap, DNS, DNSQR, DNSRR, sniff

# Read from PCAP
packets = rdpcap("traffic.pcap")
for pkt in packets:
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode()
        qtype = pkt[DNSQR].qtype  # 1=A, 16=TXT, 28=AAAA

# Live capture
def dns_callback(pkt):
    if pkt.haslayer(DNSQR):
        print(pkt[DNSQR].qname)

sniff(filter="udp port 53", prn=dns_callback, count=100)
```

## Shannon Entropy Calculation

```python
import math
from collections import Counter

def shannon_entropy(data):
    counter = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length)
                for c in counter.values())

# Normal domain: ~2.5-3.5 bits
# DNS tunnel:    ~4.0-5.0 bits
```

## DNS Tunneling Indicators

| Indicator | Threshold | Rationale |
|-----------|-----------|-----------|
| Subdomain entropy | > 3.8 | Encoded/encrypted data |
| Query length | > 50 chars | Payload in subdomain |
| TXT queries/domain | > 20/hour | Data channel |
| Unique subdomains | > 50/parent | Encoded sessions |
| Digit ratio | > 0.4 | Base64/hex encoding |

## Common DNS Tunnel Tools

| Tool | Encoding | Record Types |
|------|----------|-------------|
| iodine | Base128 | NULL, TXT, CNAME |
| dnscat2 | Hex/CNAME | TXT, MX, CNAME |
| dns2tcp | Base64 | TXT, KEY |

### References

- scapy: https://scapy.readthedocs.io/en/latest/
- DNS tunneling detection: https://www.sans.org/white-papers/dns-tunneling/
- iodine: https://github.com/yarrick/iodine
