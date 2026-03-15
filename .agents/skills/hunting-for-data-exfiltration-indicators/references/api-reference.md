# API Reference: Data Exfiltration Detection

## Exfiltration Methods (MITRE ATT&CK)

| Technique | ID | Description |
|-----------|----|-------------|
| Exfiltration Over C2 Channel | T1041 | Via existing C2 |
| Exfiltration Over Alternative Protocol | T1048 | DNS, ICMP, etc. |
| Exfiltration Over Web Service | T1567 | Cloud storage |
| Automated Exfiltration | T1020 | Scripted transfer |

## DNS Exfiltration Indicators

| Indicator | Threshold |
|-----------|-----------|
| Shannon entropy | > 3.5 |
| Subdomain length | > 40 chars |
| Query volume per domain | > 100/hour |
| TXT record responses | > 500 bytes |

## Zeek Log Fields

### conn.log
| Field | Description |
|-------|-------------|
| `ts` | Timestamp |
| `id.orig_h` | Source IP |
| `id.resp_h` | Destination IP |
| `orig_bytes` | Bytes from source |
| `resp_bytes` | Bytes from destination |

### dns.log
| Field | Description |
|-------|-------------|
| `query` | DNS query name |
| `qtype_name` | Query type (A, TXT, etc.) |
| `answers` | Response answers |

## Python Libraries

| Library | Use |
|---------|-----|
| `csv` | Parse Zeek TSV logs |
| `math` | Shannon entropy calculation |
| `collections.defaultdict` | Aggregate statistics |
| `dpkt` | PCAP parsing |
| `scapy` | Packet-level analysis |

## Shannon Entropy Formula

```
H(X) = -sum(p(x) * log2(p(x)))
```
Normal domain: H < 3.0, Exfil encoded: H > 3.5
