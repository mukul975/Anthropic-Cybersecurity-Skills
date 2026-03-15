# API Reference: Triaging Security Incidents

## requests Library (Threat Intel APIs)

### VirusTotal API v3
```python
headers = {"x-apikey": "<API_KEY>"}
# IP lookup
requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
# File hash lookup
requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers)
# Domain lookup
requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
```

### Response Fields
| Field | Description |
|-------|-------------|
| `last_analysis_stats.malicious` | Vendors detecting as malicious |
| `last_analysis_stats.undetected` | Vendors with no detection |
| `meaningful_name` | File name (for hash lookups) |
| `reputation` | Community reputation score |

## NIST SP 800-61r3 Incident Categories
| Category | Examples |
|----------|----------|
| Unauthorized Access | Credential compromise, privilege escalation |
| Denial of Service | DDoS, resource exhaustion |
| Malicious Code | Malware, ransomware, cryptominer |
| Improper Usage | Policy violation, insider threat |
| Reconnaissance | Port scan, directory enumeration |
| Web Application Attack | SQLi, XSS, SSRF |

## Severity Matrix
| Priority | Label | ACK SLA | Containment SLA |
|----------|-------|---------|-----------------|
| P1 | Critical | 15 min | 1 hour |
| P2 | High | 30 min | 4 hours |
| P3 | Medium | 2 hours | 24 hours |
| P4 | Low | 8 hours | 72 hours |

## SANS PICERL Framework
1. **Preparation** - Tools, playbooks, team readiness
2. **Identification** - Detection and triage (this skill)
3. **Containment** - Isolate affected systems
4. **Eradication** - Remove threat from environment
5. **Recovery** - Restore systems to normal operation
6. **Lessons Learned** - Post-incident review

## MITRE ATT&CK Mapping
| Technique | ID | Common Alert |
|-----------|----|--------------|
| Brute Force | T1110 | Multiple failed logins |
| PowerShell | T1059.001 | Encoded PS execution |
| Valid Accounts | T1078 | Anomalous authentication |
| Phishing | T1566 | Malicious email attachment |
| Exploit Public App | T1190 | Web attack detected |

## References
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- SANS Incident Response: https://www.sans.org/white-papers/33901/
- VirusTotal API: https://docs.virustotal.com/reference/overview
- MITRE ATT&CK: https://attack.mitre.org/
