# API Reference: C2 Beaconing Hunting

## Zeek Log Files

### conn.log Fields
| Index | Field | C2 Relevance |
|-------|-------|-------------|
| 0 | ts | Timing analysis |
| 2 | id.orig_h | Internal host |
| 4 | id.resp_h | C2 server |
| 5 | id.resp_p | C2 port |
| 8 | duration | Long = persistent C2 |
| 9 | orig_bytes | Upload size |
| 10 | resp_bytes | Download size |

### dns.log Fields
| Index | Field | C2 Relevance |
|-------|-------|-------------|
| 0 | ts | Query timing |
| 2 | id.orig_h | Querying host |
| 9 | query | Domain queried |
| 11 | answers | Resolution |
| 14 | qtype_name | Query type (TXT = tunneling) |

### http.log Fields
| Index | Field | C2 Relevance |
|-------|-------|-------------|
| 8 | host | C2 domain |
| 9 | uri | C2 path |
| 12 | user_agent | Identifies C2 framework |
| 13 | request_body_len | Upload size |
| 14 | response_body_len | Download size |

## C2 Framework Signatures

| Framework | User Agent | URI Pattern | Default Port |
|-----------|-----------|-------------|--------------|
| Cobalt Strike | Mozilla/5.0 | /submit.php, /activity | 443 |
| Metasploit | (varies) | /random 4-8 chars | 4444 |
| Empire | Mozilla/5.0 | /login/process.php | 443 |
| Sliver | (custom) | /random UUID | 443 |

## DNS Tunneling Indicators

| Indicator | Pattern |
|-----------|---------|
| Long subdomain | `[a-z0-9]{30,}\.domain\.com` |
| High query frequency | > 100 queries/hour to one domain |
| TXT record queries | Unusual volume of TXT lookups |
| High entropy | Shannon entropy > 3.5 in subdomain |

## JA3/JA3S TLS Fingerprinting

### JA3 Hash (Client)
```bash
# Zeek ssl.log field: ja3
# Known C2 JA3 hashes:
# Cobalt Strike: 72a589da586844d7f0818ce684948eea
# Metasploit: various
```

## Threat Intelligence Feeds

### Abuse.ch ThreatFox
```http
POST https://threatfox-api.abuse.ch/api/v1/
Content-Type: application/json

{"query": "search_ioc", "search_term": "1.2.3.4"}
```

### OTX AlienVault
```http
GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general
X-OTX-API-KEY: {key}
```

## RITA Beacon Analysis
```bash
rita import /path/to/zeek/logs my_dataset
rita show-beacons my_dataset
rita show-long-connections my_dataset
rita show-dns-fqdn-pairs my_dataset
```
