---
name: performing-soc2-type2-audit-preparation
description: 'Automates SOC 2 Type II audit preparation including gap assessment against
  AICPA Trust Services Criteria (CC1-CC9), evidence collection from cloud providers
  and identity systems, control testing validation, remediation tracking, and continuous
  compliance monitoring. Covers all five TSC categories (Security, Availability, Processing
  Integrity, Confidentiality, Privacy) with automated evidence gathering from AWS,
  Azure, GCP, Okta, GitHub, and Jira. Use when preparing for or maintaining SOC 2
  Type II certification.

  '
domain: cybersecurity
subdomain: governance-risk-compliance
tags:
- soc2
- compliance
- grc
- aicpa-tsc
- audit-preparation
- governance-risk-compliance
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
- GV.OC-01
- GV.RM-01
- GV.PO-01
- GV.OV-01
mitre_attack:
- T1078
- T1190
- T1059
- T1071
- T1095
---

# Performing SOC 2 Type II Audit Preparation

## When to Use

- When preparing for a SOC 2 Type II audit engagement with a CPA firm
- When conducting a gap assessment against AICPA Trust Services Criteria
- When automating evidence collection across cloud infrastructure and identity providers
- When validating that controls have operated effectively over the audit period (3-12 months)
- When building continuous compliance monitoring to maintain SOC 2 posture between audits
- When remediating control gaps identified during readiness assessment

## Prerequisites

- Familiarity with AICPA Trust Services Criteria (CC1-CC9)
- Access to cloud provider APIs (AWS, Azure, or GCP) with read-only permissions
- Access to identity provider (Okta, Azure AD, Google Workspace)
- Access to version control system (GitHub, GitLab)
- Access to ticketing system (Jira, Linear, ServiceNow)
- Python 3.8+ with `boto3`, `requests`, `pyyaml` dependencies
- Appropriate authorization to collect compliance evidence

## Instructions

### 1. Understand the Trust Services Criteria

SOC 2 is built on five Trust Services Categories defined by AICPA. Security (Common Criteria CC1-CC9) is mandatory; the others are selected based on business relevance:

| Category | Criteria | Focus |
|----------|----------|-------|
| Security (mandatory) | CC1-CC9 | Control environment, risk, access, operations, change management |
| Availability | A1 | System uptime and disaster recovery |
| Processing Integrity | PI1 | Accurate and complete data processing |
| Confidentiality | C1 | Protection of confidential information |
| Privacy | P1-P8 | Personal information lifecycle |

### 2. Common Criteria Breakdown (CC1-CC9)

**CC1 - Control Environment:** Board oversight, management structure, integrity and ethical values, HR policies, accountability.

**CC2 - Communication and Information:** Internal/external communication of security policies, system boundaries, roles, and responsibilities.

**CC3 - Risk Assessment:** Risk identification, fraud risk analysis, change impact assessment, risk tolerance definition.

**CC4 - Monitoring Activities:** Ongoing control evaluations, deficiency identification, remediation tracking, internal audit.

**CC5 - Control Activities:** Policy-to-procedure mapping, technology controls, deployment of controls across the entity.

**CC6 - Logical and Physical Access Controls:** Authentication, authorization, access provisioning/deprovisioning, physical security, encryption.

**CC7 - System Operations:** Anomaly detection, incident response, vulnerability management, change detection, event monitoring.

**CC8 - Change Management:** Change authorization, testing, approval workflows, emergency changes, rollback procedures.

**CC9 - Risk Mitigation:** Vendor risk management, business continuity, insurance, residual risk acceptance.

### 3. Conduct Gap Assessment

Before the audit period begins, perform a readiness assessment 8-12 weeks in advance:

```python
# Define control matrix against CC criteria
gap_assessment = {
    "CC1": {
        "CC1.1": {
            "criteria": "COSO Principle 1: Demonstrates commitment to integrity",
            "control": "Code of conduct signed annually by all employees",
            "evidence": "Signed acknowledgments in HR system",
            "status": "implemented",
            "gap": None,
        },
        "CC1.2": {
            "criteria": "COSO Principle 2: Board exercises oversight",
            "control": "Quarterly board security reviews",
            "evidence": "Board meeting minutes with security agenda items",
            "status": "partial",
            "gap": "No documented security committee charter",
        },
    },
}
```

### 4. Automate Evidence Collection

Collect evidence continuously throughout the audit period from integrated systems:

```python
import boto3

# CC6 Evidence: AWS IAM access controls
iam = boto3.client("iam")

# Collect MFA status for all IAM users
users = iam.list_users()["Users"]
mfa_evidence = []
for user in users:
    mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
    mfa_evidence.append({
        "user": user["UserName"],
        "mfa_enabled": len(mfa_devices["MFADevices"]) > 0,
        "created": user["CreateDate"].isoformat(),
    })

# CC7 Evidence: AWS CloudTrail logging status
cloudtrail = boto3.client("cloudtrail")
trails = cloudtrail.describe_trails()["trailList"]
logging_evidence = []
for trail in trails:
    status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
    logging_evidence.append({
        "trail": trail["Name"],
        "is_logging": status["IsLogging"],
        "multi_region": trail.get("IsMultiRegionTrail", False),
        "log_validation": trail.get("LogFileValidationEnabled", False),
    })
```

### 5. Validate Control Effectiveness

For Type II audits, demonstrate controls operated effectively over the entire audit period:

```python
import requests

# CC8 Evidence: Change management - verify all production changes
# had tickets, approvals, and testing before deployment
headers = {"Authorization": f"token {github_token}"}
prs = requests.get(
    "https://api.github.com/repos/org/repo/pulls",
    params={"state": "closed", "base": "main", "per_page": 100},
    headers=headers,
).json()

change_evidence = []
for pr in prs:
    if not pr.get("merged_at"):
        continue
    reviews = requests.get(pr["url"] + "/reviews", headers=headers).json()
    approved = any(r["state"] == "APPROVED" for r in reviews)
    change_evidence.append({
        "pr_number": pr["number"],
        "title": pr["title"],
        "merged_at": pr["merged_at"],
        "approved": approved,
    })

# Flag PRs merged without approval (control exception)
exceptions = [c for c in change_evidence if not c["approved"]]
```

### 6. Continuous Compliance Monitoring

Set up automated checks that run daily to detect control drift:

```python
# Daily compliance check - run via cron or Lambda
checks = [
    {"control": "CC6.1", "check": "All IAM users have MFA enabled"},
    {"control": "CC6.6", "check": "No public S3 buckets"},
    {"control": "CC7.1", "check": "CloudTrail logging enabled"},
    {"control": "CC7.2", "check": "GuardDuty findings under threshold"},
    {"control": "CC8.1", "check": "All PRs have required reviews"},
]

for check in checks:
    result = run_compliance_check(check["control"])
    if not result["passing"]:
        send_alert(
            channel="#compliance",
            message=f"Control drift: {check['control']} - {check['check']}",
            details=result["findings"],
        )
```

### 7. Prepare Evidence Packages for Auditors

Organize collected evidence into structured packages per criteria:

```python
evidence_package = {
    "audit_period": {"start": "2025-04-01", "end": "2026-03-31"},
    "criteria_packages": {
        "CC1_Control_Environment": {
            "CC1.1": ["signed_acknowledgments.csv"],
            "CC1.2": ["board_minutes_q1.pdf", "board_minutes_q2.pdf"],
        },
        "CC6_Logical_Physical_Access": {
            "CC6.1": ["okta_mfa_policy.json", "iam_users_mfa_status.csv"],
            "CC6.2": ["access_review_q1.csv", "access_review_q2.csv"],
            "CC6.3": ["offboarding_tickets.csv", "terminated_user_audit.csv"],
        },
        "CC7_System_Operations": {
            "CC7.1": ["cloudtrail_config.json", "siem_dashboard.png"],
            "CC7.2": ["guardduty_findings_summary.csv"],
            "CC7.3": ["vulnerability_scan_reports/"],
        },
        "CC8_Change_Management": {
            "CC8.1": ["merged_prs_with_approvals.csv"],
        },
    },
}
```

## Examples

### Automated Access Review for CC6.2

```python
import boto3
from datetime import datetime, timedelta

iam = boto3.client("iam")

# Find users with no activity in 90 days
inactive_threshold = datetime.utcnow() - timedelta(days=90)
report = iam.get_credential_report()["Content"].decode()

inactive_users = []
for line in report.strip().split("\n")[1:]:
    fields = line.split(",")
    username = fields[0]
    last_used = fields[4]
    if last_used not in ("N/A", "no_information"):
        last_date = datetime.strptime(last_used, "%Y-%m-%dT%H:%M:%S+00:00")
        if last_date < inactive_threshold:
            inactive_users.append({"user": username, "last_active": last_used})
```

### Vulnerability Management Evidence for CC7.2

```python
import requests

headers = {"Authorization": f"Bearer {scanner_token}"}
scans = requests.get(
    "https://scanner.example.com/api/v1/scans",
    params={"status": "completed", "since": "2025-04-01"},
    headers=headers,
).json()

vuln_evidence = {"scan_count": len(scans), "critical_findings": 0, "high_findings": 0}
for scan in scans:
    findings = requests.get(
        f"https://scanner.example.com/api/v1/scans/{scan['id']}/findings",
        headers=headers,
    ).json()
    vuln_evidence["critical_findings"] += len([f for f in findings if f["severity"] == "critical"])
    vuln_evidence["high_findings"] += len([f for f in findings if f["severity"] == "high"])
```

### Incident Response Evidence for CC7.3

```python
incidents = requests.get(
    "https://pagerduty.com/api/v1/incidents",
    params={"since": "2025-04-01", "until": "2026-03-31"},
    headers={"Authorization": f"Token token={pd_token}"},
).json()

ir_evidence = {
    "total_incidents": len(incidents["incidents"]),
    "incidents": [
        {
            "id": inc["id"],
            "title": inc["title"],
            "severity": inc["urgency"],
            "created": inc["created_at"],
            "resolved": inc.get("last_status_change_at"),
        }
        for inc in incidents["incidents"]
    ],
}
```
