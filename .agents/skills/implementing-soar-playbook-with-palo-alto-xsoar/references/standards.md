# Standards and References - SOAR Playbook with XSOAR

## SOAR Industry Standards

### Gartner SOAR Definition
Security Orchestration, Automation and Response (SOAR) combines:
- Security Orchestration and Automation (SOA)
- Security Incident Response Platforms (SIRP)
- Threat Intelligence Platforms (TIP)

### NIST SP 800-61 Rev 2 - Incident Handling
SOAR playbooks implement the NIST incident response lifecycle:
1. Preparation
2. Detection and Analysis
3. Containment, Eradication, and Recovery
4. Post-Incident Activity

### MITRE ATT&CK for Response
Playbooks should map containment actions to specific MITRE ATT&CK techniques being mitigated.

## XSOAR Architecture Standards

### Content Pack Structure
```
content-pack/
  Integrations/
    integration-name/
      integration-name.py
      integration-name.yml
      integration-name_test.py
  Playbooks/
    playbook-name.yml
  Scripts/
    script-name/
      script-name.py
      script-name.yml
  IncidentTypes/
  Layouts/
  Classifiers/
```

### Playbook Design Principles
1. Modular sub-playbooks for reusability
2. Error handling on every integration command
3. Manual review gates for destructive actions
4. SLA timers for response targets
5. Closing report generation for documentation

## Integration Best Practices

| Integration Category | Examples | Usage |
|---|---|---|
| SIEM | Splunk, Sentinel, QRadar | Alert ingestion, log queries |
| EDR | CrowdStrike, Defender, SentinelOne | Endpoint isolation, hash blocking |
| Email Security | O365, Proofpoint, Mimecast | Email analysis, sender blocking |
| Threat Intelligence | VirusTotal, MISP, OTX | IOC enrichment |
| Ticketing | Jira, ServiceNow | Incident tracking |
| Communication | Slack, Teams, PagerDuty | Notifications, approvals |
