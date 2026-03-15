# API Reference: Wireshark and tshark

## Live Capture
```bash
tshark -i eth0                              # Capture on interface
tshark -i eth0 -w output.pcap              # Write to file
tshark -i eth0 -a duration:60              # Capture for 60 seconds
tshark -i eth0 -f "port 80"               # BPF capture filter
tshark -D                                   # List interfaces
```

## Display Filters (Read Mode)
```bash
tshark -r capture.pcap -Y "<filter>"
```

### Common Filters
| Filter | Purpose |
|--------|---------|
| `ip.addr == 10.0.0.5` | Traffic to/from IP |
| `tcp.port == 443` | Traffic on port 443 |
| `http.request` | HTTP requests only |
| `dns.qr == 0` | DNS queries only |
| `tls.handshake.type == 1` | TLS Client Hello |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN-only |
| `frame.len > 1500` | Large frames |
| `tcp.analysis.retransmission` | Retransmissions |
| `icmp` | ICMP traffic |

## Field Extraction
```bash
tshark -r capture.pcap -T fields \
  -e frame.time -e ip.src -e ip.dst -e tcp.dstport \
  -E separator="," -E header=y
```

### Common Fields
| Field | Description |
|-------|-------------|
| `frame.time` | Packet timestamp |
| `ip.src` / `ip.dst` | Source/destination IP |
| `tcp.srcport` / `tcp.dstport` | TCP ports |
| `http.request.method` | HTTP method |
| `http.host` | HTTP Host header |
| `http.request.uri` | Request URI |
| `http.user_agent` | User-Agent |
| `dns.qry.name` | DNS query name |
| `tls.handshake.extensions_server_name` | TLS SNI |
| `tls.handshake.ja3` | JA3 fingerprint |

## Statistics
```bash
tshark -r capture.pcap -q -z conv,ip         # IP conversations
tshark -r capture.pcap -q -z endpoints,ip    # IP endpoints
tshark -r capture.pcap -q -z io,stat,60      # I/O per minute
tshark -r capture.pcap -q -z io,phs          # Protocol hierarchy
tshark -r capture.pcap -q -z http,tree       # HTTP stats
tshark -r capture.pcap -q -z dns,tree        # DNS stats
tshark -r capture.pcap -q -z expert          # Expert info
```

## Object Export
```bash
tshark -r capture.pcap --export-objects "http,/output/dir"
tshark -r capture.pcap --export-objects "smb,/output/dir"
tshark -r capture.pcap --export-objects "tftp,/output/dir"
tshark -r capture.pcap --export-objects "imf,/output/dir"
```

## Stream Following
```bash
tshark -r capture.pcap -z follow,tcp,ascii,0
tshark -r capture.pcap -z follow,http,ascii,0
tshark -r capture.pcap -z follow,tls,ascii,0
```

## Wireshark GUI Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Find packet |
| `Ctrl+G` | Go to packet |
| `Ctrl+Shift+E` | Export objects |
| `Ctrl+H` | Follow stream |

## editcap - PCAP Manipulation

```bash
editcap -A "2024-01-15 09:00" -B "2024-01-15 10:00" in.pcap out.pcap  # Time filter
editcap -c 1000 large.pcap split.pcap    # Split into 1000-packet files
editcap -F pcap in.pcapng out.pcap       # Convert format
```

## mergecap - Merge PCAPs

```bash
mergecap -w merged.pcap file1.pcap file2.pcap
```
