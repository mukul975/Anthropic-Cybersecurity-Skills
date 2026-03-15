# API Reference: Implementing Network Intrusion Prevention with Suricata

## Suricata Rule Syntax

```
action protocol src_ip src_port -> dst_ip dst_port (options;)
```

### Actions

| Action | Mode | Description |
|--------|------|-------------|
| `alert` | IDS/IPS | Generate alert |
| `pass` | IDS/IPS | Stop inspection of packet |
| `drop` | IPS only | Drop packet and generate alert |
| `reject` | IPS only | Send RST/ICMP unreachable + drop |
| `rejectsrc` | IPS only | Send RST/unreachable to source |
| `rejectboth` | IPS only | Send RST/unreachable to both |

### Example Rules

```
# Block known malicious TLS certificate
drop tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Malicious TLS Cert"; tls.cert_subject; content:"CN=badactor.com"; sid:1000001; rev:1;)

# Detect and drop SQL injection attempts
drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection Attempt"; flow:established,to_server; http.uri; pcre:"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i"; sid:1000002; rev:1;)

# Alert on DNS exfiltration (long subdomain)
alert dns $HOME_NET any -> any 53 (msg:"DNS Exfiltration Possible"; dns.query; pcre:"/^[a-z0-9]{32,}\./i"; threshold:type both, track by_src, count 10, seconds 60; sid:1000003; rev:1;)
```

## suricata-update Commands

```bash
# Update rule sources
suricata-update update-sources
suricata-update list-sources

# Enable Emerging Threats Open ruleset
suricata-update enable-source et/open

# Update rules and reload
suricata-update
suricatasc -c reload-rules
```

## Suricata CLI

```bash
# IDS mode (passive)
suricata -c /etc/suricata/suricata.yaml -i eth0

# IPS mode (inline via NFQUEUE)
suricata -c /etc/suricata/suricata.yaml -q 0

# Offline PCAP analysis
suricata -c /etc/suricata/suricata.yaml -r capture.pcap -l /var/log/suricata/

# Test configuration
suricata -T -c /etc/suricata/suricata.yaml

# Unix socket control
suricatasc -c reload-rules
suricatasc -c dump-counters
suricatasc -c iface-stat eth0
```

## EVE JSON Log Format

```json
{
  "timestamp": "2025-01-15T10:30:00.000000+0000",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "dest_ip": "10.0.0.5",
  "src_port": 52341,
  "dest_port": 443,
  "proto": "TCP",
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 2028759,
    "rev": 3,
    "signature": "ET MALWARE Cobalt Strike Beacon",
    "category": "A Network Trojan was detected",
    "severity": 1
  }
}
```

## Performance Tuning

| Setting | Default | Recommended (IPS) |
|---------|---------|-------------------|
| `max-pending-packets` | 1024 | 4096-65000 |
| `default-packet-size` | 1514 | 1514 |
| `runmode` | autofp | workers |
| `detect.profile` | medium | high |
| `mpm-algo` | auto | hs (Hyperscan) |

### References

- Suricata Docs: https://docs.suricata.io/en/latest/
- Suricata Rules Format: https://docs.suricata.io/en/latest/rules/intro.html
- ET Open Ruleset: https://rules.emergingthreats.net/open/
- suricata-update: https://suricata-update.readthedocs.io/en/latest/
