---
name: analyzing-dns-logs-for-exfiltration
description: >
  Analyzes DNS query logs to detect data exfiltration via DNS tunneling, DGA domain communication,
  and covert C2 channels using entropy analysis, query volume anomalies, and subdomain length
  detection in SIEM platforms. Use when SOC teams need to identify DNS-based threats that bypass
  traditional network security controls.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, dns, exfiltration, dns-tunneling, dga, c2-detection, splunk, threat-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing DNS Logs for Exfiltration

## When to Use

Use this skill when:
- SOC teams suspect data exfiltration through DNS tunneling to bypass firewall/proxy controls
- Threat intelligence indicates adversaries using DNS-based C2 channels (e.g., Cobalt Strike DNS beacon)
- UEBA detects anomalous DNS query volumes from specific hosts
- Malware analysis reveals DNS-over-HTTPS (DoH) or DNS tunneling capabilities

**Do not use** for standard DNS troubleshooting or availability monitoring — this skill focuses on security-relevant DNS abuse detection.

## Prerequisites

- DNS query logging enabled (Windows DNS Server, Bind, Infoblox, or Cisco Umbrella)
- DNS logs ingested into SIEM (Splunk with `Stream:DNS`, `dns` sourcetype, or Zeek DNS logs)
- Passive DNS data for historical domain resolution analysis
- Baseline of normal DNS behavior (query volume, domain distribution, TXT record frequency)
- Python with `math` and `collections` libraries for entropy calculation

## Workflow

### Step 1: Detect DNS Tunneling via Subdomain Length Analysis

DNS tunneling encodes data in subdomain labels, creating unusually long queries:

```spl
index=dns sourcetype="stream:dns" query_type IN ("A", "AAAA", "TXT", "CNAME", "MX")
| eval domain_parts = split(query, ".")
| eval subdomain = mvindex(domain_parts, 0, mvcount(domain_parts)-3)
| eval subdomain_str = mvjoin(subdomain, ".")
| eval subdomain_len = len(subdomain_str)
| eval tld = mvindex(domain_parts, -1)
| eval registered_domain = mvindex(domain_parts, -2).".".tld
| where subdomain_len > 50
| stats count AS queries, dc(query) AS unique_queries,
        avg(subdomain_len) AS avg_subdomain_len,
        max(subdomain_len) AS max_subdomain_len,
        values(src_ip) AS sources
  by registered_domain
| where queries > 20
| sort - avg_subdomain_len
| table registered_domain, queries, unique_queries, avg_subdomain_len, max_subdomain_len, sources
```

### Step 2: Detect High-Entropy Domain Queries (DGA Detection)

Domain Generation Algorithms produce random-looking domains:

```spl
index=dns sourcetype="stream:dns"
| eval domain_parts = split(query, ".")
| eval sld = mvindex(domain_parts, -2)
| eval sld_len = len(sld)
| eval char_count = sld_len
| eval vowels = len(replace(sld, "[^aeiou]", ""))
| eval consonants = len(replace(sld, "[^bcdfghjklmnpqrstvwxyz]", ""))
| eval digits = len(replace(sld, "[^0-9]", ""))
| eval vowel_ratio = if(char_count > 0, vowels / char_count, 0)
| eval digit_ratio = if(char_count > 0, digits / char_count, 0)
| where sld_len > 12 AND (vowel_ratio < 0.2 OR digit_ratio > 0.3)
| stats count AS queries, dc(query) AS unique_domains, values(src_ip) AS sources
  by query
| where unique_domains > 10
| sort - queries
```

**Python-based Shannon Entropy Calculation for DNS queries:**

```python
import math
from collections import Counter

def shannon_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0
    counter = Counter(text.lower())
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)

# Test with examples
normal_domain = "google"           # Low entropy
dga_domain = "x8kj2m9p4qw7n"      # High entropy
tunnel_subdomain = "aGVsbG8gd29ybGQ.evil.com"  # Base64 encoded data

print(f"Normal: {shannon_entropy(normal_domain)}")     # ~2.25
print(f"DGA:    {shannon_entropy(dga_domain)}")         # ~3.70
print(f"Tunnel: {shannon_entropy(tunnel_subdomain)}")   # ~3.50

# Threshold: entropy > 3.5 for subdomain = likely tunneling/DGA
```

**Splunk implementation of entropy scoring:**

```spl
index=dns sourcetype="stream:dns"
| eval domain_parts = split(query, ".")
| eval check_string = mvindex(domain_parts, 0)
| eval check_len = len(check_string)
| where check_len > 8
| eval chars = split(check_string, "")
| stats count AS total_chars, dc(chars) AS unique_chars by query, src_ip, check_string, check_len
| eval entropy_estimate = log(unique_chars, 2) * (unique_chars / check_len)
| where entropy_estimate > 3.5
| stats count AS high_entropy_queries, dc(query) AS unique_queries by src_ip
| where high_entropy_queries > 50
| sort - high_entropy_queries
```

### Step 3: Detect Anomalous DNS Query Volume

Identify hosts generating abnormal DNS traffic:

```spl
index=dns sourcetype="stream:dns" earliest=-24h
| bin _time span=1h
| stats count AS queries, dc(query) AS unique_domains by src_ip, _time
| eventstats avg(queries) AS avg_queries, stdev(queries) AS stdev_queries by src_ip
| eval z_score = (queries - avg_queries) / stdev_queries
| where z_score > 3 OR queries > 5000
| sort - z_score
| table _time, src_ip, queries, unique_domains, avg_queries, z_score
```

**Detect TXT record abuse (common tunneling method):**

```spl
index=dns sourcetype="stream:dns" query_type="TXT"
| stats count AS txt_queries, dc(query) AS unique_txt_domains,
        values(query) AS domains by src_ip
| where txt_queries > 100
| eval suspicion = case(
    txt_queries > 1000, "CRITICAL — Likely DNS tunneling",
    txt_queries > 500, "HIGH — Possible DNS tunneling",
    txt_queries > 100, "MEDIUM — Unusual TXT volume"
  )
| sort - txt_queries
| table src_ip, txt_queries, unique_txt_domains, suspicion
```

### Step 4: Detect Known DNS Tunneling Tools

Search for signatures of common DNS tunneling tools:

```spl
index=dns sourcetype="stream:dns"
| eval query_lower = lower(query)
| where (
    match(query_lower, "\.dnscat\.") OR
    match(query_lower, "\.dns2tcp\.") OR
    match(query_lower, "\.iodine\.") OR
    match(query_lower, "\.dnscapy\.") OR
    match(query_lower, "\.cobalt.*\.beacon") OR
    query_type="NULL" OR
    (query_type="TXT" AND len(query) > 100)
  )
| stats count by src_ip, query, query_type
| sort - count
```

**Detect DNS over HTTPS (DoH) bypassing local DNS:**

```spl
index=proxy OR index=firewall
dest IN ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
         "9.9.9.9", "149.112.112.112", "208.67.222.222")
dest_port=443
| stats sum(bytes_out) AS total_bytes, count AS connections by src_ip, dest
| where connections > 100 OR total_bytes > 10485760
| eval alert = "Possible DoH bypass — DNS queries sent over HTTPS to public resolver"
| sort - total_bytes
```

### Step 5: Correlate DNS Findings with Endpoint Data

Cross-reference suspicious DNS with process data:

```spl
index=dns src_ip="192.168.1.105" query="*.evil-tunnel.com" earliest=-24h
| stats count AS dns_queries, earliest(_time) AS first_query, latest(_time) AS last_query
  by src_ip, query
| join src_ip [
    search index=sysmon EventCode=3 DestinationPort=53 Computer="WORKSTATION-042"
    | stats count AS connections, values(Image) AS processes by SourceIp
    | rename SourceIp AS src_ip
  ]
| table src_ip, query, dns_queries, first_query, last_query, processes
```

### Step 6: Calculate Data Exfiltration Volume Estimate

Estimate data volume encoded in DNS queries:

```spl
index=dns src_ip="192.168.1.105" query="*.evil-tunnel.com" earliest=-24h
| eval domain_parts = split(query, ".")
| eval encoded_data = mvindex(domain_parts, 0)
| eval encoded_bytes = len(encoded_data)
| eval decoded_bytes = encoded_bytes * 0.75  -- Base64 decoding factor
| stats sum(decoded_bytes) AS total_bytes_estimated, count AS total_queries,
        earliest(_time) AS first_seen, latest(_time) AS last_seen
| eval estimated_kb = round(total_bytes_estimated / 1024, 1)
| eval estimated_mb = round(total_bytes_estimated / 1048576, 2)
| eval duration_hours = round((last_seen - first_seen) / 3600, 1)
| eval rate_kbps = round(estimated_kb / (duration_hours * 3600) * 8, 2)
| table total_queries, estimated_mb, duration_hours, rate_kbps, first_seen, last_seen
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **DNS Tunneling** | Technique encoding data within DNS queries/responses to exfiltrate data or establish C2 channels through DNS |
| **DGA** | Domain Generation Algorithm — malware technique generating pseudo-random domain names for C2 resilience |
| **Shannon Entropy** | Mathematical measure of randomness in a string — high entropy (>3.5) in domain names indicates DGA or tunneling |
| **TXT Record Abuse** | Using DNS TXT records (designed for text data) as a high-bandwidth channel for data tunneling |
| **DNS over HTTPS (DoH)** | DNS queries encrypted over HTTPS (port 443), bypassing traditional DNS monitoring |
| **Passive DNS** | Historical record of DNS resolutions showing which IPs a domain resolved to over time |

## Tools & Systems

- **Splunk Stream**: Network traffic capture add-on providing parsed DNS query data for SIEM analysis
- **Zeek (Bro)**: Network security monitor generating detailed DNS transaction logs for analysis
- **Cisco Umbrella (OpenDNS)**: Cloud DNS security platform blocking malicious domains and logging query data
- **Infoblox DNS Firewall**: DNS-layer security providing RPZ-based blocking and detailed query logging
- **Farsight DNSDB**: Passive DNS database for historical domain resolution lookups and infrastructure mapping

## Common Scenarios

- **Cobalt Strike DNS Beacon**: Detect periodic TXT queries with encoded payloads to C2 domain
- **Data Exfiltration**: Large volumes of unique subdomain queries encoding stolen data in Base64/hex
- **DGA Malware**: Detect DNS queries to algorithmically generated domains (high entropy, no web content)
- **DNS-over-HTTPS Bypass**: Employee using DoH to bypass corporate DNS filtering and monitoring
- **Slow Drip Exfiltration**: Low-volume DNS tunneling staying below threshold alerts (requires baseline comparison)

## Output Format

```
DNS EXFILTRATION ANALYSIS — WORKSTATION-042
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Period:       2024-03-14 to 2024-03-15
Source:       192.168.1.105 (WORKSTATION-042, Finance Dept)

Findings:
  [CRITICAL] DNS tunneling detected to evil-tunnel[.]com
    Query Volume:       12,847 queries in 18 hours
    Avg Subdomain Len:  63 characters (normal: <20)
    Avg Entropy:        3.82 (threshold: 3.5)
    Query Types:        TXT (89%), A (11%)
    Estimated Data:     ~4.7 MB exfiltrated via DNS
    Rate:               0.58 kbps (slow drip pattern)

  [HIGH] DGA-like domains resolved
    Unique DGA Domains: 247 domains resolved
    Pattern:            15-char random alphanumeric.xyz TLD
    Entropy Range:      3.6 - 4.1

Process Attribution:
  Process:   svchost_update.exe (masquerading — not legitimate svchost)
  PID:       4892
  Parent:    explorer.exe
  Hash:      SHA256: a1b2c3d4... (VT: 34/72 malicious — Cobalt Strike beacon)

Containment:
  [DONE] Host isolated via EDR
  [DONE] Domain evil-tunnel[.]com added to DNS sinkhole
  [DONE] Incident IR-2024-0448 created
```
