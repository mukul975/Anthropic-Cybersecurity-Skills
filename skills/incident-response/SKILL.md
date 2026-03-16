---
name: incident-response
description: Guides incident response documentation and procedures. Use when creating IR plans, documenting incidents, or developing response playbooks. Aligned with NIST SP 800-61.
domain: cybersecurity
subdomain: incident-response
tags: [nist-800-61, incident-response, playbook, containment, forensics]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Incident Response Skill

Security operations expert specializing in incident response procedures aligned with NIST SP 800-61.

## Core Expertise

- **NIST SP 800-61**: Computer Security Incident Handling Guide
- **Incident Classification**: Severity levels and categorization
- **Response Procedures**: Containment, eradication, recovery
- **Gaming Regulatory**: GLI and state notification requirements

## Case Management Integration

This skill integrates with Security Incident Response Platforms (SIRPs) for case-based incident management:

### Case Investigation Workflow

- Load complete case context including tasks, logs, observables, comments, and timeline
- Document investigation activities and findings with timestamps
- Track task progress through workflow stages
- Extract and correlate indicators of compromise (IOCs)
- Search for related incidents containing specific IOCs
- Maintain comprehensive case timeline with external events

## Incident Response Phases

### 1. Preparation

- IR plan documentation
- Team roles and contacts
- Communication templates
- Tool readiness
- Training and exercises

### 2. Detection and Analysis

- Load complete case data for active incidents
- Document findings with detailed task logs
- Search for related cases by shared IOCs
- Track investigation task status
- Assess impact using case timeline for chronology
- Classify incidents by severity and type

### 3. Containment

- **Short-term Containment**: Document actions with timestamps
- **Evidence Preservation**: Track all observables in case
- **Long-term Containment**: Update task status and timeline events
- **System Backup**: Document backup activities

### 4. Eradication

- Root cause identification
- Malware removal
- Vulnerability remediation
- System hardening

### 5. Recovery

- System restoration
- Validation testing
- Monitoring enhancement
- Return to operations

### 6. Post-Incident

- Lessons learned documentation
- Complete timeline verification
- Process improvement recommendations
- Final report generation
- Case closure with all tasks completed

## Severity Classification

| Level        | Description                                              | Response Time | Notification         |
| ------------ | -------------------------------------------------------- | ------------- | -------------------- |
| **Critical** | Business-critical system compromised, active data breach | Immediate     | Executive, Regulator |
| **High**     | Significant system compromise, potential data exposure   | 1 hour        | Management, Legal    |
| **Medium**   | Contained incident, limited impact                       | 4 hours       | Security management  |
| **Low**      | Minor incident, no data impact                           | 24 hours      | Security team        |

## Gaming Regulatory Requirements

### Notification Requirements

| Jurisdiction             | Requirement                 | Timeline           |
| ------------------------ | --------------------------- | ------------------ |
| State Gaming Commissions | Significant cyber incidents | 72 hours typically |
| PCI DSS                  | Cardholder data breach      | Immediate          |
| GDPR                     | Personal data breach        | 72 hours           |

### Evidence Retention

- Gaming records: 5+ years
- Security logs: 5+ years
- Incident documentation: Permanent

## Incident Types

### Account Compromise

- Player account takeover
- Administrative account breach
- Service account compromise

### Data Breach

- Player PII exposure
- Payment data breach
- Internal data leak

### System Compromise

- Malware infection
- Ransomware attack
- Unauthorized access

### Availability Impact

- DDoS attack
- System outage
- Service degradation

### Fraud/Abuse

- Bonus abuse ring
- Collusion detection
- Money laundering

## Playbook Template

```markdown
# Incident Response Playbook: [Incident Type]

## Overview

- **Playbook ID**: IR-XXX
- **Incident Type**: [Type]
- **Severity**: [Level]
- **Last Updated**: [Date]

## Detection

### Indicators

- [Indicator 1]
- [Indicator 2]

### Detection Sources

- [ ] SIEM alert
- [ ] EDR alert
- [ ] User report

## Triage

1. Verify alert is not false positive
2. Gather initial context
3. Determine scope

## Containment

### Immediate Actions

1. [Action 1]
2. [Action 2]

## Investigation

1. [Investigation step]
2. [Investigation step]

## Eradication

1. [Eradication step]
2. [Eradication step]

## Recovery

1. [Recovery step]
2. [Recovery step]

## Communication

### Internal

- [ ] Security management
- [ ] Executive team (if Critical/High)

### External

- [ ] Regulators (if required)
- [ ] Law enforcement (if required)
- [ ] Customers (if required)
```

## Output Formats

### Incident Report

- Executive summary
- Timeline of events
- Technical details
- Impact assessment
- Response actions
- Lessons learned
- Recommendations
