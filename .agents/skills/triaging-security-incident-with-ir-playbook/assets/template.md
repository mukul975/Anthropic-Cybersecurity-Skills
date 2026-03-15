# Incident Triage Report

## Alert Information
| Field | Value |
|-------|-------|
| Alert ID | |
| Alert Source | [SIEM/EDR/IDS/Email Gateway] |
| Alert Name/Rule | |
| Alert Time | YYYY-MM-DD HH:MM UTC |
| Triage Analyst | |
| Triage Start Time | YYYY-MM-DD HH:MM UTC |
| Triage End Time | YYYY-MM-DD HH:MM UTC |

## Alert Details
| Field | Value |
|-------|-------|
| Source IP | |
| Source Hostname | |
| Destination IP | |
| Destination Hostname | |
| Protocol/Port | |
| User Account | |
| File Hash (SHA256) | |
| Domain/URL | |

## IOC Enrichment Results

### IP Reputation
| Source | Score | Details |
|--------|-------|---------|
| VirusTotal | /100 | malicious detections |
| AbuseIPDB | % confidence | reports |
| Shodan | | Open ports/services |
| Internal Intel | | Previous incidents |

### File Hash Reputation
| Source | Score | Details |
|--------|-------|---------|
| VirusTotal | /70+ engines | Family: |
| MalwareBazaar | | Tags: |
| Internal IOC DB | | |

### Domain Reputation
| Source | Score | Details |
|--------|-------|---------|
| VirusTotal | /100 | |
| URLScan.io | | |
| PassiveTotal | | |

## Classification

### Incident Type
- [ ] Malware
- [ ] Ransomware
- [ ] Phishing
- [ ] Unauthorized Access
- [ ] Data Exfiltration
- [ ] DDoS
- [ ] Insider Threat
- [ ] Account Compromise
- [ ] Web Application Attack
- [ ] Privilege Escalation
- [ ] Other: ___________

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| | | |

## Severity Assessment

### Scoring Factors
| Factor | Rating | Score |
|--------|--------|-------|
| Asset Criticality | [Critical/High/Medium/Low] | /4 |
| Data Sensitivity | [PII-PHI/PCI/Confidential/Public] | /4 |
| Threat Status | [Active/Confirmed/Attempted/Recon] | /4 |
| Scope | [Enterprise/Department/System/User] | /4 |
| **Total** | | **/16** |

### Severity Determination
| Field | Value |
|-------|-------|
| Severity | [Critical/High/Medium/Low] |
| Priority | [P1/P2/P3/P4] |
| Response SLA | [15 min/30 min/2 hours/24 hours] |
| Justification | |

## Triage Decision
- [ ] **Escalate** - Confirmed incident requiring immediate response
- [ ] **Investigate** - Needs further analysis before confirmation
- [ ] **Monitor** - Suspicious but insufficient evidence; enhanced monitoring
- [ ] **Close - False Positive** - Benign activity; rule tuning recommended
- [ ] **Close - Informational** - Expected/authorized activity

## Playbook Assignment
| Field | Value |
|-------|-------|
| Selected Playbook | |
| Playbook Version | |
| Assigned Team | |
| Primary Analyst | |
| Backup Analyst | |

## Initial Actions Taken
- [ ] Alert acknowledged in SIEM
- [ ] IOCs enriched with threat intel
- [ ] Incident ticket created (ID: ___)
- [ ] Playbook initiated
- [ ] Response team notified
- [ ] Stakeholders informed (if P1/P2)

## Notes
[Additional context, observations, or concerns from triage]
