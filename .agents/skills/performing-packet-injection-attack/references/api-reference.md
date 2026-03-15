# API Reference: Packet Injection Attack

## Scapy Python API

```python
from scapy.all import IP, TCP, UDP, ICMP, Raw, sr1, send

# Craft and send TCP SYN
pkt = IP(dst="10.10.20.10") / TCP(dport=80, flags="S")
resp = sr1(pkt, timeout=2, verbose=0)

# Send without waiting for response
send(pkt, verbose=0)

# Fragment a packet
from scapy.all import fragment
frags = fragment(IP(dst="10.10.20.10") / ICMP() / Raw(load="X"*65500))
send(frags, verbose=0)
```

## Scapy Packet Layers

| Layer | Fields | Example |
|-------|--------|---------|
| `IP` | src, dst, ttl, flags, frag | `IP(dst="10.0.0.1", ttl=64)` |
| `TCP` | sport, dport, flags, seq, ack | `TCP(dport=80, flags="S")` |
| `UDP` | sport, dport | `UDP(dport=53)` |
| `ICMP` | type, code | `ICMP(type=8)` |
| `DNS` | qd, rd | `DNS(rd=1, qd=DNSQR(qname="test.com"))` |

## TCP Flag Values

| Flag | Value | Description |
|------|-------|-------------|
| S | SYN | Connection initiation |
| A | ACK | Acknowledgment |
| F | FIN | Connection termination |
| R | RST | Connection reset |
| P | PSH | Push data |
| U | URG | Urgent pointer |

## hping3 CLI

| Command | Description |
|---------|-------------|
| `hping3 -S -p 80 <target>` | Send SYN packets |
| `hping3 -S --flood -c 100 <target>` | Limited SYN flood test |
| `hping3 -S -p 80 -w 0 <target>` | Zero window test |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `scapy` | >=2.5 | Packet crafting, sending, and receiving |

## References

- Scapy documentation: https://scapy.readthedocs.io/
- hping3: http://www.hping.org/
- Nping (Nmap): https://nmap.org/nping/
- tcpreplay: https://tcpreplay.appneta.com/
