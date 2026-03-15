# Incident Triage with IR Playbooks - Detailed Workflow

## Triage Decision Tree

```
Alert Received
    |
    v
Is alert from trusted/tuned detection rule?
    |-- No --> Check rule logic, verify data source --> Potential false positive
    |-- Yes --> Continue
    |
    v
Does alert match known false positive pattern?
    |-- Yes --> Document, close as false positive, tune rule
    |-- No --> Continue
    |
    v
Can indicator be enriched with external threat intel?
    |-- Yes --> Enrich with VT, AbuseIPDB, OTX --> Add context
    |-- No --> Continue with available data
    |
    v
What is the incident type?
    |-- Malware --> Malware playbook
    |-- Phishing --> Phishing playbook
    |-- Unauthorized Access --> Access compromise playbook
    |-- Data Exfiltration --> Data breach playbook
    |-- Ransomware --> Ransomware playbook
    |-- DoS/DDoS --> Availability playbook
    |-- Insider Threat --> Insider playbook
    |
    v
Assign severity based on:
    - Asset criticality x Threat level x Data sensitivity
    |
    v
Route to appropriate team with playbook
```

## Severity Assignment Matrix

### Impact Score (1-4)
| Score | Asset Criticality | Examples |
|-------|------------------|----------|
| 4 | Critical | Domain controllers, production databases, financial systems |
| 3 | High | Email servers, web applications, file servers |
| 2 | Medium | Development systems, internal tools |
| 1 | Low | Test systems, non-production workstations |

### Urgency Score (1-4)
| Score | Threat Status | Indicators |
|-------|-------------|------------|
| 4 | Active exploitation | Ongoing attack, real-time data loss |
| 3 | Confirmed compromise | Evidence of breach, but not active |
| 2 | Attempted attack | Blocked attack, no evidence of success |
| 1 | Reconnaissance | Scanning, probing, no exploitation attempt |

### Final Severity = Impact x Urgency
| Score Range | Severity | Response Time | Escalation |
|------------|----------|--------------|------------|
| 12-16 | P1 Critical | Immediate (15 min) | CISO + IR Lead + Senior Analysts |
| 8-11 | P2 High | 30 minutes | IR Lead + Available Analysts |
| 4-7 | P3 Medium | 2 hours | Next available analyst |
| 1-3 | P4 Low | 24 hours (business hours) | Queued for analyst review |

## Playbook Selection Guide

### By Alert Source
| Alert Source | Likely Playbook | Key Triage Actions |
|-------------|----------------|-------------------|
| EDR - Malware detection | Malware IR | Check quarantine status, verify family |
| Email gateway - Phishing | Phishing IR | Extract IOCs, check delivery scope |
| SIEM - Authentication anomaly | Account Compromise | Verify account, check lateral movement |
| IDS/IPS - Exploit attempt | Vulnerability Exploitation | Verify patch status, check success |
| DLP - Data transfer | Data Exfiltration | Classify data, verify authorization |
| Cloud - Impossible travel | Cloud Account Compromise | Verify user, check API calls |

### By MITRE ATT&CK Tactic
| Tactic | Playbook | Priority |
|--------|----------|----------|
| Initial Access (TA0001) | Perimeter Breach | P1-P2 |
| Execution (TA0002) | Malware/Code Execution | P1-P2 |
| Persistence (TA0003) | Backdoor/Implant | P2 |
| Privilege Escalation (TA0004) | Privilege Escalation | P1 |
| Defense Evasion (TA0005) | Security Tool Bypass | P2 |
| Credential Access (TA0006) | Credential Theft | P1-P2 |
| Discovery (TA0007) | Reconnaissance | P3 |
| Lateral Movement (TA0008) | Lateral Movement | P1 |
| Collection (TA0009) | Data Staging | P2 |
| Exfiltration (TA0010) | Data Breach | P1 |
| Impact (TA0040) | Ransomware/Destruction | P1 |

## IOC Enrichment Workflow

### Step 1: Automated Enrichment
1. Submit IPs to VirusTotal, AbuseIPDB, Shodan
2. Submit file hashes to VirusTotal, MalwareBazaar, Hybrid Analysis
3. Submit domains to URLScan.io, VirusTotal, PassiveTotal
4. Check against internal IOC database and watchlists

### Step 2: Context Addition
1. Look up asset in CMDB for criticality and owner
2. Check user in HR system for role and access level
3. Verify network zone and data classification
4. Cross-reference with recent threat intelligence reports

### Step 3: Correlation
1. Search SIEM for related alerts in past 72 hours
2. Check if same IOCs appeared in other incidents
3. Correlate with ongoing threat campaigns
4. Verify if alert is part of a larger attack chain

## Triage Documentation Requirements
1. Alert details (source, time, raw data)
2. Enrichment results (reputation scores, intelligence hits)
3. Classification decision (incident type, severity, justification)
4. Selected playbook and version
5. Assigned team/analyst
6. Initial timeline of observed events
7. Known affected assets and accounts
