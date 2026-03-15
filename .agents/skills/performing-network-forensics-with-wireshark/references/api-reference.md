# API Reference: Network Forensics with Wireshark

## pyshark API

```python
import pyshark

# Open capture file
cap = pyshark.FileCapture("capture.pcap")
cap = pyshark.FileCapture("capture.pcap", display_filter="http.request")

# Access packet fields
for pkt in cap:
    print(pkt.ip.src, pkt.ip.dst)
    print(pkt.tcp.dstport)
    print(pkt.http.request_uri)
```

## tshark CLI

| Command | Description |
|---------|-------------|
| `tshark -r <pcap> -q -z conv,tcp` | TCP conversation statistics |
| `tshark -r <pcap> -Y "dns.qr==0" -T fields -e dns.qry.name` | Extract DNS queries |
| `tshark -r <pcap> --export-objects http,<dir>` | Export HTTP objects |
| `tshark -r <pcap> -q -z io,phs` | Protocol hierarchy statistics |
| `tshark -r <pcap> -q -z endpoints,ip` | IP endpoint statistics |

## Display Filters

| Filter | Description |
|--------|-------------|
| `dns.qr==0` | DNS queries only |
| `http.request` | HTTP requests |
| `tls.handshake.extensions_server_name` | TLS SNI values |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | TCP SYN packets |
| `ip.dst==<ip> && tcp.dstport==443` | Traffic to specific host |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `pyshark` | >=0.6 | Python wrapper for tshark packet analysis |
| `dpkt` | >=1.9 | Low-level PCAP parsing without tshark dependency |
| `scapy` | >=2.5 | Packet crafting and analysis |

## References

- pyshark: https://github.com/KimiNewt/pyshark
- Wireshark display filters: https://wiki.wireshark.org/DisplayFilters
- dpkt: https://github.com/kbandla/dpkt
- NetworkMiner: https://www.netresec.com/?page=NetworkMiner
