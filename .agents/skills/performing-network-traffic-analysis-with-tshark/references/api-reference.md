# Network Traffic Analysis with TShark API Reference

## TShark CLI Commands

```bash
# Protocol hierarchy statistics
tshark -r capture.pcap -q -z io,phs

# IP conversations
tshark -r capture.pcap -q -z conv,ip

# TCP conversations
tshark -r capture.pcap -q -z conv,tcp

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport

# DNS query extraction
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name -e dns.qry.type

# HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# SYN-only packets (port scan detection)
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport

# Follow TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0

# Export objects (HTTP files)
tshark -r capture.pcap --export-objects http,/tmp/exported/

# Read live capture
tshark -i eth0 -c 1000 -w output.pcap
```

## PyShark Python API

```python
import pyshark

# Read PCAP file
cap = pyshark.FileCapture("capture.pcap")
for pkt in cap:
    print(pkt.ip.src, pkt.ip.dst)

# Live capture with display filter
cap = pyshark.LiveCapture(interface="eth0", display_filter="http")
cap.sniff(timeout=30)

# Access packet layers
for pkt in cap:
    if hasattr(pkt, "dns"):
        print(pkt.dns.qry_name)
    if hasattr(pkt, "http"):
        print(pkt.http.host, pkt.http.request_uri)

# BPF capture filter
cap = pyshark.LiveCapture(interface="eth0", bpf_filter="port 53")
```

## Common Display Filters

| Filter | Purpose |
|--------|---------|
| `dns.qry.name` | DNS queries |
| `http.request` | HTTP requests |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | SYN scans |
| `tls.handshake.type==1` | TLS Client Hello |
| `ip.addr==10.0.0.1` | Traffic to/from IP |
| `tcp.analysis.retransmission` | Retransmissions |
| `frame.len > 1400` | Large frames |

## Output Formats

```bash
# JSON output
tshark -r capture.pcap -T json > output.json

# CSV-style fields
tshark -r capture.pcap -T fields -E separator=, -e ip.src -e ip.dst

# PDML (XML)
tshark -r capture.pcap -T pdml > output.xml
```
