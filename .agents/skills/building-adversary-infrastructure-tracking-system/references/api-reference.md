# API Reference: Adversary Infrastructure Tracking

## crt.sh (Certificate Transparency)
```
GET https://crt.sh/?q=%.example.com&output=json
```
| Field | Description |
|-------|-------------|
| `issuer_name` | Certificate issuer |
| `name_value` | SANs / common names |
| `serial_number` | Certificate serial |
| `not_before` / `not_after` | Validity period |

## URLhaus API
```
POST https://urlhaus-api.abuse.ch/v1/host/
Body: host=example.com
```
Returns malicious URLs hosted on the domain.

## ThreatFox API
```
POST https://threatfox-api.abuse.ch/api/v1/
Body: {"query": "search_ioc", "search_term": "1.2.3.4"}
```
| Field | Description |
|-------|-------------|
| `ioc` | IOC value |
| `threat_type` | botnet_cc, payload_delivery, etc. |
| `malware` | Associated malware family |
| `tags` | IOC tags |

## Pivoting Techniques
| Pivot | Method |
|-------|--------|
| Certificate SANs | crt.sh wildcard search |
| Shared IP | PassiveTotal, VirusTotal |
| WHOIS registrant | WHOIS history |
| DNS history | PassiveDNS (Farsight, CIRCL) |
| JARM fingerprint | TLS server fingerprinting |
| HTTP response hash | Favicon hash, body hash |

## Infrastructure Relationships
| Edge Type | Description |
|-----------|-------------|
| shared_certificate | Same TLS cert on different hosts |
| shared_ip | Multiple domains on same IP |
| shared_registrant | Same WHOIS registrant |
| shared_nameserver | Same NS records |

## MITRE ATT&CK
- T1583 - Acquire Infrastructure
- T1584 - Compromise Infrastructure
