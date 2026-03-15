# Standards and References - DNS Tunneling Detection

## MITRE ATT&CK References

| Technique | Name | Description |
|-----------|------|-------------|
| T1071.004 | Application Layer Protocol: DNS | DNS-based C2 communication |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Data theft via DNS |
| T1572 | Protocol Tunneling | IP-over-DNS tunneling |
| T1568.002 | Domain Generation Algorithms | Algorithmically generated domains |
| T1132.001 | Data Encoding: Standard Encoding | Base32/64 in DNS queries |

## DNS Tunneling Detection Thresholds

| Indicator | Threshold | Rationale |
|-----------|-----------|-----------|
| Query length | > 50 characters | Normal queries average 20-30 chars |
| Subdomain label length | > 30 characters | Max label is 63; tunneling uses near-max |
| Subdomain entropy | > 3.5 bits/char | Base32/64 encoding produces high entropy |
| Unique subdomains per domain | > 100/hour | Legitimate domains have few unique subs |
| Query volume to single domain | > 100/hour | Sustained high volume indicates tunneling |
| TXT record query ratio | > 50% to domain | TXT queries carry more data |
| NULL record queries | Any volume | Rarely used legitimately |

## DNS Tunneling Tools

| Tool | Protocol | Record Types | Data Rate | Detection Difficulty |
|------|----------|-------------|-----------|---------------------|
| iodine | IP-over-DNS | NULL, TXT, CNAME, A | ~100 Kbps | Medium |
| dnscat2 | C2 over DNS | TXT, CNAME, MX | ~10 Kbps | Medium |
| DNSExfiltrator | Exfil over DNS | TXT, A | ~5 Kbps | Medium-Hard |
| Cobalt Strike DNS | C2 | A, TXT | Variable | Hard |
| dns2tcp | TCP-over-DNS | TXT, KEY | ~50 Kbps | Medium |
| Heyoka | DNS exfiltration | All types | Variable | Hard |

## Zeek Log Fields for DNS Analysis

| Field | Description | Tunnel Relevance |
|-------|-------------|-----------------|
| query | Full DNS query name | Length and entropy analysis |
| qtype_name | Query record type | TXT/NULL/CNAME anomalies |
| answers | Response content | Response size analysis |
| rcode_name | Response code | NXDOMAIN patterns |
| id.orig_h | Source IP | Source identification |
| AA | Authoritative answer | Non-authoritative responses |
| rejected | Query rejected | Filtering effectiveness |
