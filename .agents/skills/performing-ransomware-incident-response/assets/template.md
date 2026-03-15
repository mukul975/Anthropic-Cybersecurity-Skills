# Ransomware Incident Response Report

## Incident Overview
| Field | Value |
|-------|-------|
| Incident ID | IR-YYYY-NNN |
| Date Detected | YYYY-MM-DD HH:MM UTC |
| Ransomware Family | [LockBit/BlackCat/Cl0p/etc.] |
| Variant Version | [if known] |
| Severity | [Critical/High/Medium] |
| Incident Commander | [Name] |
| Status | [Active/Contained/Eradicated/Recovered] |

## Executive Summary
[2-3 sentence summary of the ransomware incident, impact, and current status]

## Ransomware Identification
| Attribute | Details |
|-----------|---------|
| Family/Variant | |
| File Extension | |
| Ransom Note Filename | |
| Bitcoin Wallet(s) | |
| Tor Payment URL | |
| Ransom Demand | |
| Decryptor Available | Yes/No (source: ) |

## Encryption Scope

### Affected Systems
| Hostname | IP Address | OS | Role | Encryption Status | Recovery Method |
|----------|-----------|-----|------|-------------------|----------------|
| | | | | Full/Partial/None | Backup/Decrypt/Rebuild |

### Affected Data
| Data Category | Classification | Volume (GB) | Location | Encrypted | Exfiltrated |
|--------------|---------------|-------------|----------|-----------|-------------|
| | | | | Yes/No | Yes/No/Unknown |

### Encryption Statistics
- Total encrypted files: [count]
- Total affected directories: [count]
- Estimated data volume encrypted: [GB/TB]
- Encryption completion: [percentage if still in progress]

## Attack Timeline
| Date/Time (UTC) | Event | Evidence Source |
|-----------------|-------|----------------|
| | Initial access | |
| | Credential harvesting | |
| | Lateral movement began | |
| | Data exfiltration (if applicable) | |
| | Security tools disabled | |
| | VSS/backups deleted | |
| | Encryption started | |
| | Encryption detected | |
| | Containment initiated | |

## Initial Access Vector
- [ ] Phishing email (attachment/link)
- [ ] Exploited public-facing application (CVE: ___)
- [ ] Compromised VPN/RDP credentials
- [ ] Supply chain compromise
- [ ] Insider threat
- [ ] Unknown (under investigation)

## Containment Actions
- [ ] Infected systems isolated from network
- [ ] C2 IPs/domains blocked at firewall
- [ ] Compromised accounts disabled
- [ ] Lateral movement protocols blocked
- [ ] Backup systems isolated and protected
- [ ] Enhanced monitoring deployed

## Backup and Recovery Assessment

### Backup Status
| Backup Type | Status | Last Good Date | Integrity Verified | Recovery Time |
|-------------|--------|---------------|-------------------|---------------|
| Volume Shadow Copies | Available/Deleted | | Yes/No | |
| On-premise backup (Veeam/etc.) | Available/Encrypted/Offline | | Yes/No | |
| Cloud backup | Available/Compromised | | Yes/No | |
| Immutable backup | Available/N/A | | Yes/No | |
| Tape backup | Available/N/A | | Yes/No | |

### Recovery Plan
| Priority | System | Recovery Method | Estimated Time | Status |
|----------|--------|----------------|---------------|--------|
| P1 | | | | |
| P2 | | | | |
| P3 | | | | |

## Ransom Payment Decision
- [ ] Payment NOT recommended (backups available)
- [ ] Payment under consideration (legal/executive review)
- [ ] Law enforcement consulted: [FBI/CISA/Local]
- [ ] Cyber insurance carrier notified: [Yes/No]
- [ ] External IR firm engaged: [Yes/No - Firm name]

## Indicators of Compromise (IOCs)

### Network IOCs
| IOC Type | Value | Context |
|----------|-------|---------|
| IP Address | | C2 server |
| Domain | | C2 domain |
| URL | | Payment site |

### File IOCs
| IOC Type | Value | Context |
|----------|-------|---------|
| SHA256 | | Ransomware binary |
| SHA256 | | Loader/dropper |
| Filename | | Ransom note |

### Host IOCs
| IOC Type | Value | Context |
|----------|-------|---------|
| Registry key | | Persistence |
| Scheduled task | | Execution |
| Service | | Persistence |

## Notifications
- [ ] Executive leadership briefed
- [ ] Legal counsel engaged
- [ ] Cyber insurance carrier notified
- [ ] Law enforcement notified (FBI IC3, CISA)
- [ ] Regulatory notification (if required): [GDPR/HIPAA/PCI/State laws]
- [ ] Customer notification (if required)
- [ ] Sector ISAC notified

## Lessons Learned
### What Worked
-

### What Failed
-

### Recommendations
1.
2.
3.

## Approvals
| Role | Name | Signature | Date |
|------|------|-----------|------|
| Incident Commander | | | |
| CISO | | | |
| Legal Counsel | | | |
| CEO/COO | | | |
