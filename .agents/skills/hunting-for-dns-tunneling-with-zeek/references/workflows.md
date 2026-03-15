# Detailed Hunting Workflow - DNS Tunneling with Zeek

## Phase 1: Query Length and Volume Analysis

### Step 1.1 - Identify Domains with Long Queries
```spl
index=zeek sourcetype=bro_dns
| eval query_len=len(query)
| where query_len > 50
| rex field=query "\.(?<basedomain>[^.]+\.[^.]+)$"
| stats count avg(query_len) as avg_len max(query_len) as max_len dc(query) as unique_queries by id.orig_h basedomain
| where count > 50
| sort -avg_len
```

### Step 1.2 - High Volume DNS to Single Domain
```spl
index=zeek sourcetype=bro_dns
| rex field=query "\.(?<basedomain>[^.]+\.[^.]+)$"
| bin _time span=1h
| stats count by id.orig_h basedomain _time
| where count > 100
| sort -count
```

## Phase 2: Entropy Analysis

### Step 2.1 - Shannon Entropy Calculation
```python
import math
from collections import Counter

def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

# Flag subdomains with entropy > 3.5
```

### Step 2.2 - Splunk Entropy Approximation
```spl
index=zeek sourcetype=bro_dns
| rex field=query "^(?<subdomain>[^.]+)"
| where len(subdomain) > 20
| eval has_numbers=if(match(subdomain, "[0-9]"), 1, 0)
| eval has_mixed_case=if(match(subdomain, "[A-Z]") AND match(subdomain, "[a-z]"), 1, 0)
| stats count avg(len(subdomain)) as avg_sub_len sum(has_numbers) as numeric_count by id.orig_h basedomain
| eval numeric_ratio=numeric_count/count
| where avg_sub_len > 25 AND numeric_ratio > 0.3
```

## Phase 3: Record Type Analysis

### Step 3.1 - Unusual Record Types
```spl
index=zeek sourcetype=bro_dns
| where qtype_name IN ("TXT", "NULL", "CNAME", "MX", "KEY", "SRV")
| rex field=query "\.(?<basedomain>[^.]+\.[^.]+)$"
| stats count dc(query) as unique by id.orig_h basedomain qtype_name
| where count > 50
| sort -count
```

## Phase 4: RITA Automated Analysis

```bash
# Full Zeek log import and DNS analysis
rita import /opt/zeek/logs/current dns_hunt
rita show-dns-tunneling dns_hunt
rita show-exploded-dns dns_hunt | sort -k2 -n -r | head -20
```

## Phase 5: Correlation and Response

### Step 5.1 - Map DNS Source to Endpoint
Correlate dns.log source IPs with DHCP logs or endpoint inventory to identify affected hosts and processes.

### Step 5.2 - Response Actions
1. DNS sinkhole the identified tunneling domain
2. Block at DNS resolver and firewall
3. Isolate source endpoint
4. Capture memory and disk forensics
5. Assess scope of data exfiltration
