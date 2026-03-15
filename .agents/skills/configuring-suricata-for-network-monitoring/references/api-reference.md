# Suricata API Reference

## Suricata CLI

```bash
# Validate configuration
suricata -T -c /etc/suricata/suricata.yaml -v

# Run IDS mode with AF_PACKET
suricata -c /etc/suricata/suricata.yaml --af-packet=eth1 -D

# Run IPS mode with NFQueue
suricata -c /etc/suricata/suricata.yaml -q 0 -D

# Analyze PCAP file
suricata -c /etc/suricata/suricata.yaml -r capture.pcap -l /tmp/output/

# Reload rules without restart (Unix socket)
suricatasc -c reload-rules
```

## suricata-update CLI

```bash
# Update all enabled rule sources
suricata-update

# List available sources
suricata-update list-sources

# Enable a source
suricata-update enable-source et/open
suricata-update enable-source oisf/trafficid

# Disable specific SIDs via /etc/suricata/disable.conf
echo "2100498" >> /etc/suricata/disable.conf
```

## EVE JSON Event Types

| event_type | Description |
|------------|-------------|
| `alert` | IDS/IPS alert with signature match |
| `http` | HTTP request/response metadata |
| `dns` | DNS query and answer records |
| `tls` | TLS handshake with JA3/JA3S hashes |
| `flow` | Network flow summary on completion |
| `files` | Extracted file metadata with hashes |
| `stats` | Engine performance statistics |
| `anomaly` | Protocol anomaly detection events |
| `smtp` | SMTP transaction metadata |
| `ssh` | SSH handshake with HASSH fingerprint |

## EVE JSON Parsing with jq

```bash
# Top alert signatures
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn

# Extract alert IOCs as CSV
jq -r 'select(.event_type=="alert") | [.timestamp,.src_ip,.dest_ip,.alert.signature] | @csv' eve.json

# JA3 fingerprint analysis
jq -r 'select(.event_type=="tls") | [.src_ip,.tls.ja3.hash,.tls.sni] | @csv' eve.json

# DNS query analysis
jq -r 'select(.event_type=="dns" and .dns.type=="query") | [.src_ip,.dns.rrname] | @csv' eve.json

# Performance stats (check for drops)
jq 'select(.event_type=="stats") | .stats.capture' eve.json | tail -1
```

## Suricata Rule Syntax

```
action protocol src dst (msg:"text"; content:"match"; sid:N; rev:N;)

# JA3-based detection
alert tls $HOME_NET any -> any any (
    msg:"Suspicious JA3"; ja3.hash; content:"<hash>"; sid:9000010; rev:1;
)

# DNS keyword detection
alert dns any any -> any any (
    msg:"DNS tunneling"; dns.query; content:"."; offset:50; sid:9000011; rev:1;
)
```

## Unix Socket Control (suricatasc)

```bash
suricatasc -c reload-rules        # Reload rules live
suricatasc -c iface-list          # List monitored interfaces
suricatasc -c capture-mode        # Show capture mode
suricatasc -c uptime              # Show uptime
```
