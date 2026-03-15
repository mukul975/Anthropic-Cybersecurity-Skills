# API Reference: Network Traffic Incident Analysis

## tshark - CLI Wireshark

### Basic Syntax
```bash
tshark -r <pcap_file> [options]
```

### Display Filters
```bash
tshark -r capture.pcap -Y "ip.addr==10.0.0.5"
tshark -r capture.pcap -Y "tcp.port==445"         # SMB
tshark -r capture.pcap -Y "http.request"           # HTTP requests
tshark -r capture.pcap -Y "dns.qr==0"              # DNS queries
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0"  # SYN only
```

### Field Extraction
```bash
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport \
  -Y "tcp.flags.syn==1"
```

### Statistics
```bash
tshark -r capture.pcap -q -z conv,ip       # IP conversations
tshark -r capture.pcap -q -z endpoints,ip  # IP endpoints
tshark -r capture.pcap -q -z io,stat,60    # I/O stats per minute
tshark -r capture.pcap -q -z http,tree     # HTTP request tree
tshark -r capture.pcap -q -z dns,tree      # DNS query tree
```

### Object Export
```bash
tshark -r capture.pcap --export-objects "http,/tmp/http_objects"
tshark -r capture.pcap --export-objects "smb,/tmp/smb_objects"
```

## Zeek - Network Security Monitor

### PCAP Analysis
```bash
zeek -r capture.pcap
zeek -r capture.pcap local     # With local policy scripts
```

### Output Logs
| Log File | Content |
|----------|---------|
| `conn.log` | TCP/UDP/ICMP connections |
| `dns.log` | DNS queries and responses |
| `http.log` | HTTP requests |
| `ssl.log` | TLS/SSL handshakes |
| `files.log` | File transfers |
| `notice.log` | Security notices |

### Zeek-Cut Field Extraction
```bash
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service
cat dns.log | zeek-cut query qtype_name answers
cat http.log | zeek-cut host uri method user_agent
```

## Suricata - IDS/IPS

### PCAP Analysis
```bash
suricata -r capture.pcap -l /tmp/output -k none
suricata -r capture.pcap -S custom.rules -l /tmp/output
```

### Output Files
| File | Content |
|------|---------|
| `fast.log` | One-line alert format |
| `eve.json` | JSON event log (detailed) |
| `stats.log` | Engine performance statistics |

## Lateral Movement Ports

| Port | Service | Significance |
|------|---------|-------------|
| 445 | SMB | File shares, PsExec, WMI |
| 3389 | RDP | Remote Desktop |
| 5985/5986 | WinRM | PowerShell Remoting |
| 22 | SSH | Secure Shell |
| 135 | RPC | DCOM, WMI |
| 139 | NetBIOS | Legacy file sharing |

## Scapy - Packet Analysis (Python)

### PCAP Reading
```python
from scapy.all import rdpcap, IP, TCP
packets = rdpcap("capture.pcap")
for pkt in packets:
    if IP in pkt and TCP in pkt:
        print(pkt[IP].src, pkt[TCP].dport)
```

## NetworkMiner - Artifact Extraction

### Syntax
```bash
NetworkMiner --inputfile capture.pcap --outputdir /tmp/artifacts
```
Extracts: files, images, credentials, sessions, DNS, parameters
