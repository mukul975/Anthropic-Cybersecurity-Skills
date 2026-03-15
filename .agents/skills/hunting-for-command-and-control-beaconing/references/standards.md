# Standards and References - C2 Beaconing Detection

## MITRE ATT&CK Command and Control (TA0011)

| Technique | Name | Indicators |
|-----------|------|-----------|
| T1071.001 | Web Protocols | HTTP/HTTPS periodic connections |
| T1071.004 | DNS | DNS query patterns, tunneling |
| T1573.001 | Symmetric Cryptography | Encrypted C2 channels |
| T1573.002 | Asymmetric Cryptography | TLS C2 with custom certs |
| T1572 | Protocol Tunneling | DNS over HTTPS, ICMP tunneling |
| T1568.002 | Domain Generation Algorithms | Random domain patterns |
| T1568.001 | Fast Flux DNS | Rapidly rotating IPs |
| T1132.001 | Standard Encoding | Base64 in C2 traffic |
| T1132.002 | Non-Standard Encoding | Custom encoding schemes |
| T1095 | Non-Application Layer Protocol | ICMP, raw TCP/UDP C2 |
| T1090 | Proxy | Multi-hop C2 infrastructure |
| T1090.002 | External Proxy | External relay points |
| T1102 | Web Service | Legitimate services for C2 |
| T1105 | Ingress Tool Transfer | Downloading tools via C2 |

## Beaconing Detection Thresholds

| Metric | Threshold | Notes |
|--------|-----------|-------|
| Coefficient of Variation | < 0.20 | Strong periodicity indicator |
| Min Beacon Interval | > 30 seconds | Below may be streaming |
| Unique Destinations | Single domain/IP | C2 typically targets 1 destination |
| Session Duration | > 24 hours | Persistent C2 activity |
| Data Size Consistency | < 20% variance | Heartbeat-like payload sizes |
| Connection Count | > 50/day | Meaningful sample for analysis |

## Known C2 Framework Signatures

| Framework | Default Interval | Jitter | Protocol | JA3 Hash |
|-----------|-----------------|--------|----------|----------|
| Cobalt Strike | 60s | 0-50% | HTTPS, DNS | Multiple known hashes |
| Metasploit Meterpreter | 5s | 0% | TCP, HTTP/S | Framework-dependent |
| Sliver | 60s | 0-30% | HTTPS, mTLS, WireGuard | Varies |
| Brute Ratel C4 | 60s | 10-30% | HTTPS, DNS | Varies |
| Havoc | 5s | 0-20% | HTTPS | Varies |
| Mythic | Configurable | Configurable | HTTP/S, TCP | Agent-dependent |
| Covenant | 10s | 10% | HTTP/S | .NET TLS |
| Empire/Starkiller | 5s | 0-20% | HTTP/S | Python TLS |

## Data Sources

| Source | Data Type | Use |
|--------|-----------|-----|
| Zeek conn.log | Connection metadata | Duration, bytes, frequency |
| Zeek dns.log | DNS queries | Domain analysis, DGA detection |
| Zeek http.log | HTTP headers | User-agent, URI patterns |
| Zeek ssl.log | TLS metadata | JA3, certificate analysis |
| Proxy logs | Full URL, user agent | Content inspection |
| Sysmon Event 3 | Network connections | Process-to-connection mapping |
| Sysmon Event 22 | DNS queries | DNS process attribution |
| NetFlow/IPFIX | Network flows | Volume and timing analysis |
| Firewall logs | Allow/deny with timing | Connection frequency |

## DNS Tunneling Indicators

| Indicator | Description |
|-----------|-------------|
| High query volume | > 100 queries/hour to single domain |
| Long subdomain labels | > 30 characters in subdomain |
| High entropy subdomains | Base32/64 encoded data |
| TXT record queries | Large TXT records for data transfer |
| NULL/CNAME responses | Unusual record types |
| Unique subdomain count | Many unique subdomains per domain |
