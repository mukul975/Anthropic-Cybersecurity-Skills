# DNS Exfiltration Detection Reference

## Zeek dns.log Field Reference (TSV Format)

| Field | Type | Description |
|-------|------|-------------|
| `ts` | time | Timestamp of the DNS request |
| `uid` | string | Unique connection identifier |
| `id.orig_h` | addr | Source IP address |
| `id.orig_p` | port | Source port |
| `id.resp_h` | addr | Destination IP (DNS server) |
| `id.resp_p` | port | Destination port (usually 53) |
| `proto` | enum | Transport protocol (udp/tcp) |
| `trans_id` | count | DNS transaction ID |
| `rtt` | interval | Round trip time |
| `query` | string | The domain name queried |
| `qclass` | count | Query class value |
| `qclass_name` | string | Query class name (C_INTERNET) |
| `qtype` | count | Query type value |
| `qtype_name` | string | Query type name (A, AAAA, TXT, MX, CNAME, NULL) |
| `rcode` | count | Response code value |
| `rcode_name` | string | Response code name (NOERROR, NXDOMAIN, SERVFAIL) |
| `AA` | bool | Authoritative Answer flag |
| `TC` | bool | Truncation flag |
| `RD` | bool | Recursion Desired flag |
| `RA` | bool | Recursion Available flag |
| `Z` | count | Reserved field |
| `answers` | vector | Resource record answers |
| `TTLs` | vector | TTL values for answer RRs |
| `rejected` | bool | Whether query was rejected |

## zeek-cut Usage

```bash
# Extract specific fields from dns.log
cat dns.log | zeek-cut ts id.orig_h query qtype_name answers

# Filter TXT queries (common in DNS tunneling)
cat dns.log | zeek-cut query qtype_name | grep TXT

# Count queries per domain
cat dns.log | zeek-cut query | rev | cut -d. -f1-2 | rev | sort | uniq -c | sort -rn
```

## RITA Beacon Detection

```bash
# Import Zeek logs into RITA
rita import /opt/zeek/logs/current rita-dataset

# Analyze for beaconing
rita show-beacons rita-dataset

# Show DNS tunneling indicators
rita show-dns rita-dataset

# HTML report
rita html-report rita-dataset /var/www/html/rita-report
```

## Suricata DNS Exfiltration Rules

```
# Detect long DNS queries (potential tunneling)
alert dns any any -> any any (msg:"Possible DNS tunneling - long query"; \
  dns.query; content:"|00|"; byte_test:1,>,50,0,relative; \
  sid:1000001; rev:1;)

# Detect TXT record queries to unusual domains
alert dns any any -> any any (msg:"Suspicious DNS TXT query"; \
  dns_query; pcre:"/^[a-z0-9]{30,}\./i"; sid:1000002; rev:1;)
```

## Splunk SPL for DNS Exfiltration

```spl
index=zeek sourcetype=zeek_dns
| eval subdomain_len=len(mvindex(split(query, "."), 0))
| where subdomain_len > 50
| stats count dc(query) as unique_queries by "id.orig_h" query
| where unique_queries > 100
| sort -unique_queries
```
