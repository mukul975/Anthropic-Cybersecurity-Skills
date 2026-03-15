# API Reference: DNS Exfiltration Detection Tools

## Shannon Entropy Calculation

### Python Implementation
```python
import math
from collections import Counter

def shannon_entropy(text):
    counter = Counter(text.lower())
    length = len(text)
    return -sum((c/length) * math.log2(c/length) for c in counter.values())
```

### Threshold Values
| Entropy | Classification |
|---------|---------------|
| < 2.5 | Normal domain (e.g., "google") |
| 2.5 - 3.5 | Borderline (monitor) |
| > 3.5 | Suspicious (likely DGA/tunneling) |
| > 4.0 | High confidence malicious |

## Splunk DNS Queries

### Tunneling Detection
```spl
index=dns sourcetype="stream:dns"
| eval subdomain_len=len(mvindex(split(query,"."),0))
| where subdomain_len > 50
| stats count by registered_domain, src_ip
```

### DGA Detection
```spl
index=dns
| eval sld=mvindex(split(query,"."), -2)
| where len(sld) > 12
| stats count, dc(query) AS unique by src_ip
```

### Volume Anomaly
```spl
index=dns earliest=-24h
| bin _time span=1h
| stats count AS queries by src_ip, _time
| eventstats avg(queries) AS avg_q, stdev(queries) AS stdev_q by src_ip
| eval z_score=(queries - avg_q) / stdev_q
| where z_score > 3
```

### TXT Record Abuse
```spl
index=dns query_type="TXT"
| stats count AS txt_queries by src_ip
| where txt_queries > 100
```

## Zeek DNS Log Format

### Log Fields (dns.log)
| Column | Field | Description |
|--------|-------|-------------|
| 0 | ts | Timestamp |
| 2 | id.orig_h | Source IP |
| 4 | id.resp_h | DNS server IP |
| 9 | query | Query domain name |
| 13 | qtype_name | Query type (A, TXT, CNAME) |
| 15 | rcode_name | Response code |
| 21 | answers | Response answers |

### Zeek CLI Analysis
```bash
cat dns.log | zeek-cut query qtype_name id.orig_h | sort | uniq -c | sort -rn
```

## DNS Tunneling Tools (Detection Signatures)

| Tool | DNS Pattern |
|------|-------------|
| iodine | `*.pirate.sea` (TXT/NULL records) |
| dnscat2 | `*.dnscat.` prefix in queries |
| dns2tcp | `*.dns2tcp.` pattern |
| Cobalt Strike DNS | Periodic TXT queries with encoded payloads |

## Passive DNS Lookup APIs

### Farsight DNSDB
```bash
curl -H "X-API-Key: $KEY" \
  "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/evil.com/A"
```

### VirusTotal Domain Resolutions
```bash
curl -H "x-apikey: $KEY" \
  "https://www.virustotal.com/api/v3/domains/evil.com/resolutions"
```

## Cisco Umbrella (OpenDNS) Investigate API

### Domain Categorization
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://investigate.api.umbrella.com/domains/categorization/evil.com"
```

### Security Information
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://investigate.api.umbrella.com/security/name/evil.com"
```
