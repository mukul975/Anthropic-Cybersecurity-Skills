# Standards and References - Beaconing Frequency Analysis

## MITRE ATT&CK Command and Control (TA0011)

| Technique | Name | Beacon Indicators |
|-----------|------|-------------------|
| T1071.001 | Web Protocols | HTTP/HTTPS periodic connections with regular intervals |
| T1071.004 | DNS | DNS query patterns, tunneling with high entropy subdomains |
| T1573.001 | Symmetric Cryptography | Encrypted C2 channels with consistent packet sizes |
| T1573.002 | Asymmetric Cryptography | TLS C2 with custom or self-signed certificates |
| T1572 | Protocol Tunneling | DNS-over-HTTPS, ICMP tunneling with periodic patterns |
| T1568.002 | Domain Generation Algorithms | Algorithmically generated domains with high entropy |
| T1568.001 | Fast Flux DNS | Rapidly rotating IP addresses for C2 infrastructure |
| T1132.001 | Standard Encoding | Base64/hex encoded data in C2 traffic |
| T1095 | Non-Application Layer Protocol | ICMP, raw TCP/UDP for covert C2 |
| T1090 | Proxy | Multi-hop C2 infrastructure obscuring origin |
| T1102 | Web Service | C2 over legitimate cloud services |

## Beaconing Detection Thresholds

| Metric | Threshold | Rationale |
|--------|-----------|-----------|
| Coefficient of Variation (CV) | < 0.20 | Strong indicator of periodic automated communication |
| Minimum Beacon Interval | > 30 seconds | Below this may be streaming or polling traffic |
| Maximum Beacon Interval | < 86400 seconds | Beyond 24 hours reduces statistical significance |
| Minimum Connection Count | > 50 per 24 hours | Needed for reliable statistical analysis |
| Data Size CV | < 0.30 | Consistent payloads suggest automated heartbeats |
| Domain Age | < 30 days | Newly registered domains associated with C2 infrastructure |

## Known C2 Framework Default Beacon Profiles

| Framework | Default Interval | Default Jitter | Protocols | Detection Notes |
|-----------|-----------------|----------------|-----------|-----------------|
| Cobalt Strike | 60s | 0-50% | HTTPS, DNS | Malleable C2 profiles can change all defaults |
| Sliver | 60s | 0-30% | HTTPS, mTLS, WireGuard, DNS | Supports domain fronting |
| Brute Ratel C4 | 60s | 10-30% | HTTPS, DNS, SMB | Designed to evade EDR detection |
| Metasploit Meterpreter | 5s | 0% | TCP, HTTP/S | Highly configurable via handlers |
| Havoc | 5s | 0-20% | HTTPS | Demon agent with sleep obfuscation |
| Mythic | Configurable | Configurable | HTTP/S, TCP, WebSocket | Agent-dependent behavior |
| Covenant | 10s | 10% | HTTP/S | .NET-based C2 framework |
| Empire/Starkiller | 5s | 0-20% | HTTP/S | Python-based listeners |

## Statistical Methods for Beacon Detection

| Method | Description | Best For |
|--------|-------------|----------|
| Coefficient of Variation | stdev/mean of intervals | Regular beacons with low jitter |
| Fast Fourier Transform (FFT) | Frequency domain analysis | Detecting periodic signals in noisy data |
| Autocorrelation | Self-correlation at various lags | Identifying repeating patterns |
| Median Absolute Deviation | Robust measure of variability | Beacon detection resistant to outliers |
| Kullback-Leibler Divergence | Distribution comparison | Comparing observed intervals to uniform distribution |

## RITA Beacon Scoring Algorithm

RITA scores beacons on a 0-1 scale using:
- **Timestamp score**: Regularity of connection intervals
- **Data size score**: Consistency of bytes transferred
- **Connection count**: Volume of connections in analysis window
- **Duration**: How long the beaconing pattern has persisted

Composite score above 0.70 is considered high-confidence beaconing.
