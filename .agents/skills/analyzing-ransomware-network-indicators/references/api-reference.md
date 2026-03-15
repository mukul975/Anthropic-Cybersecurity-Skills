# Ransomware Network Indicator Analysis API Reference

## Zeek conn.log Fields

| Field | Description | Example |
|-------|-------------|---------|
| `ts` | Connection timestamp (epoch) | 1609459200.123 |
| `uid` | Unique connection ID | CYxTKo2zkGkGbfJFi |
| `id.orig_h` | Source IP | 192.168.1.100 |
| `id.orig_p` | Source port | 49152 |
| `id.resp_h` | Destination IP | 185.220.101.1 |
| `id.resp_p` | Destination port | 443 |
| `proto` | Protocol | tcp |
| `duration` | Connection duration (seconds) | 0.5 |
| `orig_bytes` | Bytes sent by originator | 1024 |
| `resp_bytes` | Bytes sent by responder | 512 |
| `conn_state` | Connection state | SF |

## Beaconing Detection Algorithm

```
1. Group connections by (src_ip, dst_ip, dst_port)
2. Sort timestamps within each group
3. Calculate intervals: t[i+1] - t[i]
4. Compute statistics:
   - mean_interval = mean(intervals)
   - stddev = stdev(intervals)
   - coefficient_of_variation = stddev / mean_interval
5. Flag as beaconing if CV < 0.3 (regular interval pattern)
   - CV < 0.1 = critical (highly regular)
   - CV 0.1-0.3 = high (moderately regular)
```

## TOR Exit Node Detection

```bash
# Fetch current TOR exit node list
curl -s https://check.torproject.org/torbulkexitlist > tor_exits.txt

# Alternative: Dan.me.uk TOR list
curl -s https://www.dan.me.uk/torlist/?exit > tor_exits_alt.txt

# Cross-reference with Zeek conn.log
zeek-cut id.resp_h < conn.log | sort -u | comm -12 - tor_exits_sorted.txt
```

## RITA (Real Intelligence Threat Analytics) for Zeek

```bash
# Import Zeek logs into RITA
rita import /opt/zeek/logs/current rita_db

# Analyze beaconing
rita show-beacons rita_db

# Show long connections
rita show-long-connections rita_db

# DNS analysis
rita show-exploded-dns rita_db
```

## Zeek CLI for Live Capture

```bash
# Analyze PCAP with Zeek
zeek -r capture.pcap

# Live capture on interface
zeek -i eth0 local.zeek

# Extract conn.log fields
zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < conn.log
```

## MITRE ATT&CK Mapping

| Technique | ID | Network Indicator |
|-----------|----|--------------------|
| Application Layer Protocol | T1071 | C2 beaconing patterns |
| Encrypted Channel | T1573 | TOR/encrypted C2 traffic |
| Exfiltration Over C2 Channel | T1041 | High outbound byte ratio |
| Data Encrypted for Impact | T1486 | Ransomware encryption |
