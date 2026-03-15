# API Reference: NetFlow v9/IPFIX Analysis

## Python netflow Library
```python
import netflow
# Parse a raw NetFlow packet
packet, templates = netflow.parse_packet(raw_bytes, templates={})
# templates must persist between calls for v9/IPFIX
for flow in packet.flows:
    flow.IPV4_SRC_ADDR  # Source IP
    flow.IPV4_DST_ADDR  # Destination IP
    flow.L4_SRC_PORT    # Source port
    flow.L4_DST_PORT    # Destination port
    flow.PROTOCOL       # IP protocol (6=TCP, 17=UDP)
    flow.IN_BYTES       # Bytes transferred
    flow.IN_PKTS        # Packet count
    flow.TCP_FLAGS      # TCP flags bitmask
    flow.FIRST_SWITCHED # Flow start time
    flow.LAST_SWITCHED  # Flow end time
```

## CLI Tools
```bash
python -m netflow.collector -p 9995 -D /tmp/flows  # Collector
python -m netflow.analyzer -f /tmp/flows/*.json     # Analyzer
```

## NetFlow v9 Field Types
| Field | ID | Description |
|-------|-----|-------------|
| IN_BYTES | 1 | Input bytes |
| IN_PKTS | 2 | Input packets |
| PROTOCOL | 4 | IP protocol |
| L4_SRC_PORT | 7 | Source port |
| IPV4_SRC_ADDR | 8 | Source IPv4 |
| L4_DST_PORT | 11 | Destination port |
| IPV4_DST_ADDR | 12 | Destination IPv4 |
| TCP_FLAGS | 6 | TCP flags |
| FIRST_SWITCHED | 22 | Flow start sysUpTime |
| LAST_SWITCHED | 21 | Flow end sysUpTime |

## Detection Algorithms
| Pattern | Method | Threshold |
|---------|--------|-----------|
| Port scan | Unique dst_ports per src-dst pair | >20 ports |
| Network sweep | Unique dst_ips per source | >50 hosts |
| Exfiltration | Total bytes per src-dst pair | >100MB |
| C2 beaconing | Interval jitter ratio | <0.15 |
