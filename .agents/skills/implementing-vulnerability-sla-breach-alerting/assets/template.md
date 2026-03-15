# Vulnerability SLA Policy Template

## 1. Purpose

This policy establishes remediation timelines for security vulnerabilities based on severity classification, defines escalation procedures for SLA breaches, and specifies reporting requirements for compliance tracking.

## 2. Scope

This policy applies to all information systems, applications, and infrastructure components managed by [Organization Name].

## 3. SLA Definitions

| Severity | CVSS Range | Remediation Timeline | Grace Period | Escalation Path |
|----------|-----------|---------------------|--------------|-----------------|
| Critical | 9.0 - 10.0 | 48 hours | 12 hours | Asset Owner -> Security Director -> CISO |
| High | 7.0 - 8.9 | 15 calendar days | 5 days | Asset Owner -> Team Lead -> Security Director |
| Medium | 4.0 - 6.9 | 60 calendar days | 14 days | Asset Owner -> Team Lead |
| Low | 0.1 - 3.9 | 90 calendar days | 30 days | Asset Owner |

## 4. Exception Process

### 4.1 Exception Request Requirements
- CVE identifier and affected system details
- Business justification for extension
- Compensating controls implemented
- Proposed new remediation date
- Risk acceptance signature from system owner and CISO

### 4.2 Maximum Exception Duration
- Critical: 14 days maximum extension
- High: 30 days maximum extension
- Medium: 60 days maximum extension
- Low: 90 days maximum extension

## 5. Alerting Configuration

### 5.1 Notification Schedule
```
80% SLA elapsed -> Warning to asset owner (email + Slack)
100% SLA elapsed -> Breach alert (email + Slack + PagerDuty for Critical/High)
SLA + 24 hours -> Escalation Level 1 (team lead)
SLA + 72 hours -> Escalation Level 2 (director)
SLA + 7 days -> Escalation Level 3 (CISO)
```

### 5.2 Notification Channels
- **Email**: All severity levels
- **Slack**: High and Critical severity
- **PagerDuty**: Critical severity SLA breaches only
- **Jira**: Automatic ticket creation for all findings

## 6. Reporting Requirements

### 6.1 Weekly Report
- Count of open findings by severity
- Count of SLA breaches by severity
- Top 5 assets with most open findings
- Remediation velocity trend

### 6.2 Monthly Report
- Overall SLA compliance rate by severity
- Mean time to remediate by severity
- Exception count and approval rate
- Quarter-over-quarter improvement trends

### 6.3 Executive Dashboard
- Overall compliance percentage
- Risk exposure trend (critical/high open count over time)
- Team/business unit comparison
- Regulatory compliance status (PCI, SOC2, HIPAA)

## 7. Compliance Mapping

| Regulation | Requirement | SLA Alignment |
|-----------|------------|---------------|
| PCI DSS 4.0 | Req 6.3.3 | Critical/High within 30 days |
| SOC 2 | CC7.1 | Evidence of SLA tracking and remediation |
| HIPAA | 164.312(a)(1) | Risk-based remediation timeline |
| CISA BOD 22-01 | KEV remediation | 14 days for KEV-listed CVEs |
| NIST CSF 2.0 | ID.RA-01 | Risk-ranked vulnerability management |

## 8. Roles and Responsibilities

- **Asset Owner**: Remediate within SLA, request exceptions when needed
- **Security Team**: Monitor SLA compliance, manage alerting system
- **Team Lead**: Review team SLA metrics, escalate blockers
- **CISO**: Approve critical exceptions, review monthly metrics
