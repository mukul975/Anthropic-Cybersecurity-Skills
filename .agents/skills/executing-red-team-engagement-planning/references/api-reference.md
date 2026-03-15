# API Reference: Red Team Engagement Planning

## MITRE ATT&CK Framework

### Tactics (Enterprise)
| ID | Tactic |
|----|--------|
| TA0043 | Reconnaissance |
| TA0042 | Resource Development |
| TA0001 | Initial Access |
| TA0002 | Execution |
| TA0003 | Persistence |
| TA0004 | Privilege Escalation |
| TA0005 | Defense Evasion |
| TA0006 | Credential Access |
| TA0007 | Discovery |
| TA0008 | Lateral Movement |
| TA0009 | Collection |
| TA0011 | Command and Control |
| TA0010 | Exfiltration |
| TA0040 | Impact |

### ATT&CK Navigator API
```http
GET https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

## Red Team Tools API References

### Cobalt Strike — Teamserver
```
./teamserver <IP> <password> <malleable_c2_profile>
```

### GoPhish — Campaign API
```http
POST https://gophish-server:3333/api/campaigns/
Authorization: Bearer {api_key}

{
  "name": "Spearphishing Test",
  "template": {"name": "IT Support"},
  "url": "https://phish.example.com",
  "smtp": {"name": "smtp_config"},
  "groups": [{"name": "Target Group"}]
}
```

### BloodHound — Data Collection
```bash
# SharpHound collection
SharpHound.exe -c All --domain corp.local
# or via Python
bloodhound-python -d corp.local -u user -p pass -c all
```

## Engagement Plan Structure

### Key Sections
| Section | Content |
|---------|---------|
| Scope | IP ranges, domains, systems in/out |
| Rules of Engagement | Authorization, boundaries |
| Objectives | Goals mapped to business risk |
| Scenarios | Attack paths and techniques |
| Timeline | Phases with milestones |
| Communication | Deconfliction, reporting |
| Data Handling | Encryption, retention, destruction |

## PTES (Penetration Testing Execution Standard)

### Phases
1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post-Exploitation
7. Reporting

## Report Template Fields

| Field | Description |
|-------|-------------|
| Executive Summary | Business impact overview |
| Scope & Methodology | What was tested and how |
| Findings | Vulnerabilities with CVSS scores |
| Attack Narrative | Timeline of red team actions |
| Detection Gaps | What blue team missed |
| Recommendations | Prioritized remediation |
