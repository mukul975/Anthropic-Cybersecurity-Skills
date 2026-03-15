# API Reference — Detecting Ransomware Precursors in Network Traffic

## Zeek (Bro) Log Fields

### conn.log
| Field | Type | Description |
|-------|------|-------------|
| `ts` | time | Connection start timestamp (Unix epoch) |
| `id.orig_h` | addr | Source IP address |
| `id.orig_p` | port | Source port |
| `id.resp_h` | addr | Destination IP address |
| `id.resp_p` | port | Destination port |
| `proto` | enum | Transport protocol (tcp/udp/icmp) |
| `orig_bytes` | count | Bytes sent by originator |
| `resp_bytes` | count | Bytes sent by responder |
| `conn_state` | string | Connection state (SF=normal, S0=no reply, REJ=rejected) |
| `duration` | interval | Duration of connection |

### smb_files.log
| Field | Type | Description |
|-------|------|-------------|
| `action` | enum | SMB action (SMB_FILE_OPEN, SMB_FILE_WRITE, SMB_FILE_DELETE) |
| `path` | string | Full UNC path accessed |
| `name` | string | Filename |
| `size` | count | File size in bytes |
| `id.orig_h` | addr | Source host (accessor) |
| `id.resp_h` | addr | Target host |

### kerberos.log
| Field | Type | Description |
|-------|------|-------------|
| `request_type` | string | KRB_AS_REQ, KRB_TGS_REQ |
| `client` | string | Client principal |
| `service` | string | Service principal (SPN) |
| `success` | bool | Whether request succeeded |
| `error_msg` | string | Error type (e.g., KDC_ERR_PREAUTH_REQUIRED) |

## Suricata CLI

### Start in IDS mode
```bash
suricata -c /etc/suricata/suricata.yaml -i eth0
```

### Start in IPS mode (NFQUEUE)
```bash
suricata -c /etc/suricata/suricata.yaml -q 0
# Configure iptables to send traffic to NFQUEUE:
iptables -I FORWARD -j NFQUEUE --queue-num 0
```

### Run on pcap file
```bash
suricata -c /etc/suricata/suricata.yaml -r capture.pcap -l /var/log/suricata/
```

### Update rules with suricata-update
```bash
suricata-update                          # Update all enabled sources
suricata-update list-sources             # List available rule sources
suricata-update enable-source et/open    # Enable Emerging Threats Open
suricata-update enable-source ptresearch/attackdetection  # PT Research rules
suricata-update update-sources           # Refresh source index
suricata-update --no-reload              # Update without live reload
```

### Reload rules without restart
```bash
kill -USR2 $(pidof suricata)
# Or via Unix socket:
suricatasc -c reload-rules
```

### Query eve.json for alerts
```bash
# Ransomware-related alerts in last hour
jq 'select(.event_type=="alert") | select(.alert.signature | test("ransomware|cobalt|mimikatz|psexec";"i"))' \
  /var/log/suricata/eve.json | jq -r '[.timestamp,.src_ip,.dest_ip,.alert.signature] | @tsv'

# Top 10 alert signatures
jq -r 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json | \
  sort | uniq -c | sort -rn | head -10
```

## RITA (Real Intelligence Threat Analytics)

### Import Zeek logs and analyze
```bash
rita import --input /var/log/zeek/current/ --database my_network
rita analyze my_network
```

### Beacon detection output
```bash
rita show-beacons my_network --human-readable
# Columns: Score | Source | Dest | Connections | Avg Bytes | TS Delta
# Score 0.9+ = high confidence beacon
```

### DNS tunneling detection
```bash
rita show-exploded-dns my_network | head -20
rita show-long-connections my_network --human-readable
```

## Splunk SPL — Ransomware Precursor Queries

### Internal lateral movement via SMB/RDP/WinRM
```spl
index=zeek sourcetype=zeek_conn
  id.resp_p IN (445, 135, 3389, 5985, 5986)
  id.orig_h IN 10.0.0.0/8
  id.resp_h IN 10.0.0.0/8
| stats dc(id.resp_h) as targets count as conns by id.orig_h
| where targets >= 10
| sort -targets
```

### Detect beaconing (regular connection intervals)
```spl
index=zeek sourcetype=zeek_conn
| bucket _time span=1m
| stats count as conns by id.orig_h, id.resp_h, id.resp_p, _time
| stats stdev(conns) as jitter avg(conns) as avg_conns count as minutes
    by id.orig_h, id.resp_h, id.resp_p
| where minutes > 10 AND jitter < 2 AND avg_conns > 0
| eval beacon_score = round(1 - (jitter / (avg_conns + 0.001)), 2)
| where beacon_score > 0.8
| sort -beacon_score
```

## abuse.ch Threat Intelligence Feeds

### Feodo Tracker (C2 IPs — Cobalt Strike, BazarLoader)
```bash
# CSV format: first_seen,dst_ip,dst_port,c2_status,malware
curl -s https://feodotracker.abuse.ch/downloads/ipblocklist.csv | \
  grep -v "^#" | awk -F, '{print $2}' > /tmp/c2_ips.txt
```

### ThreatFox IOC API
```bash
# Query recent ransomware IOCs
curl -s -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{"query":"get_iocs","days":7,"tag":"ransomware"}' | \
  jq '.data[] | [.ioc_value,.ioc_type,.malware,.confidence_level] | @tsv' -r
```

## MITRE ATT&CK Ransomware Precursor Techniques
| Technique | ID | Network Indicator |
|-----------|----|-------------------|
| Remote Services: SMB/WMI | T1021.002 | SMB port 445 traffic to many hosts |
| OS Credential Dumping: DCSync | T1003.006 | DRS GetNCChanges from non-DC |
| Kerberoasting | T1558.003 | TGS-REQ for many SPNs |
| Command & Control | T1071.001 | Regular HTTPS beaconing |
| Lateral Tool Transfer | T1570 | Large SMB file writes across hosts |
| Network Service Scanning | T1046 | Port sweeps on 445/3389/135 |
