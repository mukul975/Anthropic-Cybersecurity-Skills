# API Reference: Network Covert Channel Detection

## Scapy - Packet Analysis

### DNS Tunneling Detection
```python
from scapy.all import rdpcap, DNS, DNSQR, IP

packets = rdpcap("capture.pcap")
for pkt in packets:
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode().rstrip(".")
        src = pkt[IP].src
        qtype = pkt[DNSQR].qtype  # 1=A, 16=TXT, 28=AAAA
```

### ICMP Payload Extraction
```python
from scapy.all import ICMP, Raw

for pkt in packets:
    if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        icmp_type = pkt[ICMP].type  # 8=echo-request, 0=echo-reply
```

## Zeek - Covert Channel Detection

### DNS Tunneling Indicators
```zeek
@load base/protocols/dns
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count) {
    if (|query| > 60)
        print fmt("Long DNS query: %s from %s", query, c$id$orig_h);
}
```

### Configuration
```bash
zeek -r capture.pcap local
# Outputs: dns.log, conn.log, weird.log
```

## tshark - Protocol Filtering

### DNS Analysis
```bash
tshark -r capture.pcap -Y "dns" -T fields \
  -e ip.src -e dns.qry.name -e dns.qry.type -e frame.len

# Filter long DNS queries
tshark -r capture.pcap -Y "dns.qry.name matches \"^.{60,}\"" -T fields -e dns.qry.name
```

### ICMP Payload Analysis
```bash
tshark -r capture.pcap -Y "icmp && data.len > 64" -T fields \
  -e ip.src -e ip.dst -e icmp.type -e data.len -e data.data
```

## DNS Tunneling Tools

| Tool | Technique | Detection Method |
|------|-----------|-----------------|
| iodine | TXT/NULL/CNAME records | High entropy subdomains |
| dns2tcp | TXT records | Encoded query names |
| dnscat2 | TXT/CNAME/MX/A records | Base32/Base64 subdomain patterns |
| DNSExfiltrator | TXT records | High query volume to single domain |

## Entropy Thresholds

| Range | Interpretation |
|-------|---------------|
| < 2.0 | Normal domain labels (English words) |
| 2.0-3.5 | Possibly encoded but may be legitimate |
| 3.5-5.0 | Likely Base32/Base64 encoded (tunneling) |
| > 5.0 | Encrypted/random data (strong tunneling indicator) |

## Covert Channel Categories

| Channel Type | Protocol | Detection Method |
|-------------|----------|-----------------|
| DNS Tunneling | DNS (53/udp) | Subdomain entropy, query volume |
| ICMP Tunnel | ICMP (type 8/0) | Payload size, entropy, volume |
| HTTP Header | HTTP (80/tcp) | Cookie size, custom header entropy |
| Protocol Abuse | IP options, GRE | Unusual protocol numbers |
| Timing Channel | TCP | Inter-packet timing analysis |
