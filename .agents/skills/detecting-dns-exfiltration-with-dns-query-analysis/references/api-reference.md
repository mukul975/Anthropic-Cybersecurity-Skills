# API Reference: Detecting DNS Exfiltration

## Shannon Entropy Calculation

```python
import math
from collections import Counter

def entropy(text):
    freq = Counter(text)
    length = len(text)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

# Normal subdomain: entropy ~2.5-3.0
# Encoded data: entropy >3.5-4.0
```

## Detection Thresholds

| Metric | Normal | Suspicious |
|--------|--------|------------|
| Subdomain entropy | < 3.0 | > 3.5 |
| Subdomain length | < 20 chars | > 40 chars |
| TXT record ratio | < 5% | > 30% |
| Queries to single domain | < 50/hr | > 100/hr |

## Zeek dns.log Fields

```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id
        query qclass qclass_name qtype qtype_name rcode rcode_name
```

## DNS Tunneling Tools

| Tool | Protocol | Indicators |
|------|----------|------------|
| iodine | TXT/NULL/CNAME | Encoded subdomains, high volume |
| dnscat2 | TXT/CNAME | Base32/Base64 subdomains |
| dns2tcp | TXT | Long TXT responses |

## Splunk SPL Detection

```spl
index=dns
| eval subdomain=replace(query, "\.[^.]+\.[^.]+$", "")
| eval entropy=...
| where len(subdomain) > 40 AND query_count > 100
| stats count by query, src_ip
```

## Suricata DNS Rules

```
alert dns any any -> any 53 (msg:"DNS Tunnel - Long Query"; \
  dns.query; content:"."; offset:50; sid:2000001;)
```

## CLI Usage

```bash
python agent.py --dns-log dns.log --format zeek
python agent.py --dns-log dns.log --entropy-threshold 3.8 --length-threshold 50
```
