---
name: triaging-security-incident
description: Performs initial triage of security incidents using the NIST SP 800-61r3 and SANS PICERL frameworks, classifying incident type, assigning priority by business impact, and routing to the appropriate response team. Use when a SIEM/EDR alert needs human classification, concurrent alerts must be prioritized, or a user report or threat-intel IOC match requires initial incident categorization. Do not use for triage driven by structured IR playbooks and SIEM case-management queries - use building-incident-response-playbook.
domain: cybersecurity
subdomain: incident-response
tags:
- incident-triage
- NIST-800-61
- SANS-PICERL
- severity-classification
- SOC-operations
mitre_attack:
- T1486
- T1490
- T1070
- T1078
version: 1.0.0
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
---

# Triaging Security Incidents

## When to Use

- A SIEM or EDR alert fires and requires human classification before escalation
- Multiple concurrent alerts arrive and the SOC must prioritize response order
- An end user reports suspicious activity and the incident needs initial categorization
- A threat intelligence feed matches an IOC observed in the environment

**Do not use** for routine vulnerability scanning results or compliance audit findings that do not represent active security incidents.

## Prerequisites

- Access to SIEM platform (Splunk, Elastic, Microsoft Sentinel) with current alert data
- Incident classification taxonomy aligned to NIST SP 800-61r3 categories
- Predefined severity matrix mapping asset criticality to threat type
- Contact roster for escalation paths (Tier 1 through Tier 3 and CIRT)
- Asset inventory with business criticality ratings

## Workflow

### Step 1: Collect Initial Alert Data

Gather all available context from the triggering alert before making classification decisions:

- **Alert source**: Which detection system generated the alert (EDR, SIEM, IDS/IPS, firewall, user report)
- **Timestamp**: When the event occurred and when it was detected (dwell time gap)
- **Affected assets**: Hostnames, IP addresses, user accounts involved
- **Alert fidelity**: Historical true-positive rate for this detection rule
- **Raw evidence**: Log entries, packet captures, process execution chains

```
Example SIEM alert context:
Source:       CrowdStrike Falcon
Detection:    Suspicious PowerShell Execution (T1059.001)
Host:         WORKSTATION-FIN-042
User:         jsmith@corp.example.com
Timestamp:    2025-11-15T14:23:17Z
Severity:     High (detection rule confidence: 92%)
Process:      powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...
Parent:       outlook.exe (PID 4812)
```

### Step 2: Classify the Incident Type

Map the alert to a standard incident category per NIST SP 800-61r3:

| Category | Examples |
|----------|----------|
| Unauthorized Access | Compromised credentials, privilege escalation, IDOR |
| Denial of Service | Volumetric DDoS, application-layer flood, resource exhaustion |
| Malicious Code | Malware execution, ransomware detonation, cryptominer |
| Improper Usage | Policy violation, insider data exfiltration, shadow IT |
| Reconnaissance | Port scanning, directory enumeration, credential spraying |
| Web Application Attack | SQL injection, XSS, SSRF exploitation |

### Step 3: Assign Severity Using Impact Matrix

Calculate severity by combining asset criticality with threat severity:

```
Severity = f(Asset Criticality, Threat Type, Data Sensitivity, Lateral Movement Potential)

Critical (P1): Crown jewel systems compromised, active data exfiltration, ransomware spreading
High (P2):     Production system compromise, confirmed malware execution, privileged account takeover
Medium (P3):   Non-production compromise, unsuccessful exploitation attempt, single endpoint malware
Low (P4):      Reconnaissance activity, policy violation, benign true positive
```

Response SLA targets:
- P1: Acknowledge within 15 minutes, containment within 1 hour
- P2: Acknowledge within 30 minutes, containment within 4 hours
- P3: Acknowledge within 2 hours, investigation within 24 hours
- P4: Acknowledge within 8 hours, investigation within 72 hours

### Step 4: Perform Initial Enrichment

Before escalation, enrich the alert with contextual data:

- **Threat intelligence**: Check IOCs (IP, hash, domain) against TI platforms (VirusTotal, OTX, MISP)
- **Asset context**: Query CMDB for asset owner, business function, data classification
- **User context**: Check identity provider for recent authentication anomalies, MFA status
- **Historical correlation**: Search for related alerts on the same host/user in the past 30 days
- **Network context**: Verify if source/destination IPs are internal, known partners, or external threat actors

### Step 5: Document and Escalate

Create a structured triage record and route to the appropriate response tier:

```
Incident Triage Record
━━━━━━━━━━━━━━━━━━━━━
Ticket ID:       INC-2025-1547
Triage Analyst:  [analyst name]
Triage Time:     2025-11-15T14:35:00Z (12 min from alert)
Classification:  Malicious Code - Macro-based initial access
Severity:        P2 - High
Affected Assets: WORKSTATION-FIN-042 (Finance dept, handles PII)
Affected Users:  jsmith@corp.example.com
IOCs Identified: powershell.exe spawned by outlook.exe, encoded command
TI Matches:      Base64 payload matches known Qakbot loader pattern
Escalation:      Tier 2 - Malware IR team
Recommended:     Isolate endpoint, preserve memory dump, block sender domain
```

### Step 6: Initiate Containment Hold

If severity is P1 or P2, initiate immediate containment actions while awaiting full investigation:

- Network-isolate the affected endpoint via EDR (CrowdStrike contain, Defender isolate)
- Disable compromised user accounts in Active Directory or identity provider
- Block identified malicious IPs/domains at firewall and DNS sinkhole
- Preserve volatile evidence (memory dump) before any remediation

## Implementation: Tooling Commands

The workflow above is framework-driven; the commands below operationalize each step against common SOC tooling (Splunk, TheHive, VirusTotal/AbuseIPDB, PagerDuty).

### Pull and acknowledge new alerts (Splunk + TheHive)

```bash
# Splunk: list new critical/high notable events
index=notable status=new severity IN ("critical","high")
| table _time, rule_name, src, dest, severity, description
| sort -_time

# Acknowledge the notable in SIEM to prevent duplicate triage
curl -X POST "https://splunk.local:8089/services/notable_update" \
  -H "Authorization: Bearer $SPLUNK_TOKEN" \
  -d "ruleUIDs=$RULE_UID&status=1&comment=Triage+initiated+by+analyst"

# TheHive: list new alerts awaiting triage
curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" \
  "https://thehive.local/api/v1/query?name=list-alerts" \
  -H "Content-Type: application/json" \
  -d '{"query":[{"_name":"listAlert"},{"_name":"filter","_field":"status","_value":"New"}]}'
```

### Enrich indicators (VirusTotal + AbuseIPDB)

```bash
# VirusTotal: IP and file-hash reputation
curl -s "https://www.virustotal.com/api/v3/ip_addresses/$SRC_IP" \
  -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats'
curl -s "https://www.virustotal.com/api/v3/files/$FILE_HASH" \
  -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats'

# AbuseIPDB: source IP reputation over the last 90 days
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$SRC_IP&maxAgeInDays=90" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | jq '.data'
```

### Score severity programmatically

Turns the impact matrix from Step 3 into a reproducible score (max 16):

```python
python3 -c "
severity_score = 0
# Asset criticality: Critical=4, High=3, Medium=2, Low=1
severity_score += 4  # Critical server
# Data sensitivity: PII/PHI=4, PCI=3, Confidential=2, Public=1
severity_score += 3  # PCI data
# Scope: Enterprise=4, Department=3, Single system=2, Single user=1
severity_score += 2  # Single system
# Threat status: Active=4, Recent=3, Historical=2, Potential=1
severity_score += 4  # Active threat

if severity_score >= 12: print('CRITICAL - P1')
elif severity_score >= 9: print('HIGH - P2')
elif severity_score >= 6: print('MEDIUM - P3')
else: print('LOW - P4')
print(f'Score: {severity_score}/16')
"
```

### Open and update the case (TheHive)

```bash
# Create the incident case with playbook and affected-system metadata
curl -X POST "https://thehive.local/api/v1/case" \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "IR-2025-XXX: [Incident Type] - [Brief Description]",
    "description": "Triage summary and initial findings",
    "severity": 3, "tlp": 2, "pap": 2,
    "tags": ["ransomware", "triage-complete"],
    "customFields": {
      "playbook": {"string": "ransomware_v2"},
      "affected_systems": {"integer": 5}
    }
  }'

# Update the case with triage decision and severity justification
curl -X PATCH "https://thehive.local/api/v1/case/$CASE_ID" \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "InProgress",
    "customFields": {
      "triage_analyst": {"string": "analyst_name"},
      "severity_justification": {"string": "Critical asset + active threat + PCI data"}
    }
  }'
```

### Escalate by severity (PagerDuty)

```bash
# Check on-call before paging
curl -s "https://pagerduty.com/api/v2/oncalls?schedule_ids[]=$SCHEDULE_ID" \
  -H "Authorization: Token token=$PD_TOKEN" | jq '.oncalls[].user.summary'

# Page by severity tier:
#   P1/Critical: IR lead + senior analysts + CISO
#   P2/High:     IR lead + available analysts
#   P3/Medium:   next available analyst
#   P4/Low:      queue for business hours
curl -X POST "https://events.pagerduty.com/v2/enqueue" \
  -H "Content-Type: application/json" \
  -d '{
    "routing_key": "'$PD_ROUTING_KEY'",
    "event_action": "trigger",
    "payload": {
      "summary": "P1 Security Incident: Ransomware detected on PROD-DB-01",
      "severity": "critical",
      "source": "SIEM-Splunk",
      "custom_details": {"incident_id": "IR-2025-042", "playbook": "ransomware_v2"}
    }
  }'
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Triage** | Rapid assessment process to classify and prioritize security incidents based on severity and business impact |
| **PICERL** | SANS incident response framework: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned |
| **Dwell Time** | Duration between initial compromise and detection; average is 10 days per Mandiant M-Trends 2025 |
| **True Positive Rate** | Percentage of alerts from a detection rule that represent genuine security incidents |
| **Crown Jewel Assets** | Systems and data critical to business operations whose compromise would cause severe organizational impact |
| **Alert Fatigue** | Degraded analyst performance caused by high volumes of low-fidelity or false-positive alerts |
| **Mean Time to Acknowledge (MTTA)** | Average time from alert generation to analyst acknowledgment; key SOC performance metric |

## Tools & Systems

- **Splunk Enterprise Security**: SIEM platform for alert aggregation, correlation, and triage workflow management
- **CrowdStrike Falcon**: EDR platform providing endpoint telemetry, detection, and one-click host containment
- **TheHive**: Open-source incident response platform for case management, task tracking, and team collaboration
- **MISP**: Threat intelligence sharing platform for IOC enrichment during triage
- **Cortex XSOAR**: SOAR platform for automating enrichment playbooks and triage decision trees

## Common Scenarios

### Scenario: Encoded PowerShell from Email Client

**Context**: SOC analyst receives a P2 alert showing `powershell.exe` with a Base64-encoded command spawned as a child process of `outlook.exe` on a finance department workstation.

**Approach**:
1. Decode the Base64 payload to determine the command intent
2. Check the parent process chain for anomalies (Outlook spawning PowerShell is abnormal)
3. Query VirusTotal for the decoded payload hash
4. Correlate with email gateway logs to identify the triggering email and sender
5. Check if other recipients in the organization received the same email
6. Isolate the endpoint and escalate to Tier 2 with full triage context

**Pitfalls**:
- Dismissing encoded PowerShell as a false positive without decoding the payload
- Failing to check for lateral spread to other recipients of the same phishing email
- Remediating the endpoint before capturing volatile memory evidence

## Output Format

```
INCIDENT TRIAGE REPORT
======================
Ticket:          INC-[YYYY]-[NNNN]
Date/Time:       [ISO 8601 timestamp]
Triage Analyst:  [Name]
Time to Triage:  [minutes from alert to classification]

CLASSIFICATION
Type:            [NIST category]
Severity:        [P1-P4] - [Critical/High/Medium/Low]
Confidence:      [High/Medium/Low]
MITRE ATT&CK:   [Technique ID and name]

AFFECTED SCOPE
Assets:          [hostname(s), IP(s)]
Users:           [account(s)]
Data at Risk:    [classification level]
Business Unit:   [department]

EVIDENCE SUMMARY
[Bullet list of key observations]

ENRICHMENT RESULTS
TI Matches:      [Yes/No - details]
Historical:      [Related prior incidents]
Asset Criticality: [rating]

RECOMMENDED ACTIONS
1. [Immediate action]
2. [Investigation step]
3. [Escalation target]

ESCALATION
Routed To:       [Team/Individual]
SLA Target:      [Containment deadline]
```
