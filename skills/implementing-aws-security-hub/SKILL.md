---
name: implementing-aws-security-hub
description: >
  This skill covers deploying AWS Security Hub as a centralized cloud security posture
  management platform that aggregates findings from GuardDuty, Inspector, Macie, and
  third-party tools. It details enabling security standards like CIS AWS Foundations
  Benchmark, configuring automated remediation, and building executive dashboards for
  compliance tracking across multi-account AWS organizations.
domain: cybersecurity
subdomain: cloud-security
tags: [aws-security-hub, cspm, compliance-automation, security-standards, finding-aggregation]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing AWS Security Hub

## When to Use

- When establishing a centralized security findings dashboard across multiple AWS accounts
- When enabling automated compliance checks against CIS, PCI-DSS, NIST, or AWS Foundational Security Best Practices
- When integrating findings from GuardDuty, Inspector, Macie, and third-party security tools
- When building automated remediation workflows for recurring security misconfigurations
- When preparing compliance evidence for auditors requiring continuous posture monitoring

**Do not use** for real-time threat detection (see detecting-cloud-threats-with-guardduty), for Azure compliance monitoring (see securing-azure-with-microsoft-defender), or for deep vulnerability scanning of container images (see securing-container-registry).

## Prerequisites

- AWS Organization with a designated security administrator account
- AWS Config enabled in all target accounts and regions
- GuardDuty, Inspector, and Macie activated for finding integration
- IAM permissions for securityhub:* and config:* in the administrator account

## Workflow

### Step 1: Enable Security Hub with Standards

Activate Security Hub in the delegated administrator account and enable security standards. AWS Security Hub CSPM supports CIS AWS Foundations Benchmark v5.0, AWS Foundational Security Best Practices, PCI DSS v3.2.1, and NIST SP 800-53.

```bash
# Enable Security Hub with standards
aws securityhub enable-security-hub \
  --enable-default-standards \
  --tags '{"Environment":"production","ManagedBy":"security-team"}'

# Enable CIS AWS Foundations Benchmark v5.0
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/5.0.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"}
  ]'

# Verify enabled standards
aws securityhub get-enabled-standards \
  --query 'StandardsSubscriptions[*].[StandardsArn,StandardsStatus]' --output table
```

### Step 2: Configure Multi-Account Aggregation

Designate a Security Hub administrator and automatically enroll all organization member accounts. Configure cross-region aggregation to consolidate findings into a single region.

```bash
# Designate delegated admin
aws securityhub enable-organization-admin-account \
  --admin-account-id 111122223333

# Auto-enable for all org members
aws securityhub update-organization-configuration \
  --auto-enable \
  --organization-configuration '{"ConfigurationType": "CENTRAL"}'

# Enable cross-region aggregation
aws securityhub create-finding-aggregator \
  --region-linking-mode ALL_REGIONS
```

### Step 3: Integrate Security Services and Third-Party Tools

Configure product integrations to receive findings from AWS services and partner security tools. Map third-party findings to AWS Security Finding Format (ASFF).

```bash
# List available product integrations
aws securityhub describe-products \
  --query 'Products[*].[ProductName,CompanyName,ProductSubscriptionResourcePolicy]' --output table

# Enable specific integrations
aws securityhub enable-import-findings-for-product \
  --product-arn "arn:aws:securityhub:us-east-1::product/aws/guardduty"

aws securityhub enable-import-findings-for-product \
  --product-arn "arn:aws:securityhub:us-east-1::product/aws/inspector"

# Import custom findings using ASFF format
aws securityhub batch-import-findings --findings '[{
  "SchemaVersion": "2018-10-08",
  "Id": "custom-finding-001",
  "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
  "GeneratorId": "custom-scanner",
  "AwsAccountId": "123456789012",
  "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
  "Title": "Unpatched OpenSSL in production ALB backend",
  "Description": "CVE-2024-12345 detected on backend instances",
  "Severity": {"Label": "HIGH"},
  "Resources": [{"Type": "AwsEc2Instance", "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123"}]
}]'
```

### Step 4: Build Automated Remediation

Create Security Hub custom actions linked to EventBridge rules and Lambda functions for one-click or fully automated remediation of common findings.

```bash
# Create a custom action for remediation
aws securityhub create-action-target \
  --name "IsolateInstance" \
  --description "Isolate EC2 instance by replacing security groups" \
  --id "IsolateInstance"

# EventBridge rule for automated remediation of specific controls
aws events put-rule \
  --name SecurityHubAutoRemediate \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Compliance": {"Status": ["FAILED"]},
        "Severity": {"Label": ["CRITICAL", "HIGH"]},
        "GeneratorId": ["aws-foundational-security-best-practices/v/1.0.0/S3.1"]
      }
    }
  }'
```

### Step 5: Monitor Compliance Scores and Generate Reports

Track security scores across standards, monitor compliance drift over time, and generate reports for audit evidence.

```bash
# Get security score for a standard
aws securityhub get-security-control-definition \
  --security-control-id "S3.1"

# List all failed controls with counts
aws securityhub get-findings \
  --filters '{
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --sort-criteria '{"Field": "SeverityLabel", "SortOrder": "desc"}' \
  --max-items 50
```

## Key Concepts

| Term | Definition |
|------|------------|
| Security Standard | Pre-packaged set of controls mapped to compliance frameworks such as CIS, PCI-DSS, NIST 800-53, and AWS best practices |
| Security Control | Individual automated check that evaluates a specific AWS resource configuration against a security requirement |
| ASFF | AWS Security Finding Format, a standardized JSON schema for normalizing findings from all integrated security products |
| Compliance Score | Percentage of controls in a passing state within a given security standard, calculated per account and aggregated at the organization level |
| Finding Aggregator | Cross-region mechanism that consolidates findings from all enabled regions into a single administrator region |
| Custom Action | User-defined action that can be triggered from the Security Hub console to invoke EventBridge rules for manual or automated response |

## Tools & Systems

- **AWS Security Hub CSPM**: Core platform for automated security posture checks and finding aggregation
- **AWS Config**: Underlying configuration recorder that Security Hub relies on for resource evaluation
- **Amazon EventBridge**: Event routing service for connecting Security Hub findings to automated remediation workflows
- **AWS Systems Manager**: Automation documents that Security Hub can invoke for remediation of common misconfigurations
- **AWS Audit Manager**: Generates audit-ready reports using Security Hub findings as evidence

## Common Scenarios

### Scenario: Failed CIS Controls Across 50 Accounts

**Context**: An enterprise enables CIS AWS Foundations Benchmark v5.0 and discovers 340 failed controls across 50 accounts, primarily in IAM password policy, CloudTrail configuration, and VPC flow log enablement.

**Approach**:
1. Export all FAILED findings grouped by control ID to identify the most prevalent issues
2. Prioritize Critical and High severity controls that affect the most accounts
3. Create Systems Manager Automation documents for the top 10 recurring failures
4. Deploy automated remediation via EventBridge for controls like S3.1 (block public access) and CloudTrail.1 (enable multi-region trail)
5. Schedule weekly compliance score reviews and track improvement over a 90-day remediation window

**Pitfalls**: Enabling automated remediation for all controls at once can break production workloads that legitimately require public S3 access or specific network configurations. Always test remediation in a staging account first.

## Output Format

```
AWS Security Hub Compliance Report
====================================
Organization: acme-corp
Administrator Account: 111122223333
Report Date: 2025-02-23
Standards Enabled: CIS v5.0, AWS FSBP v1.0, PCI DSS v3.2.1

COMPLIANCE SCORES:
  CIS AWS Foundations Benchmark v5.0: 78%
  AWS Foundational Security Best Practices: 85%
  PCI DSS v3.2.1: 72%

TOP FAILED CONTROLS (by account count):
  [S3.1]   Block public access settings enabled      - 23/50 accounts FAILED
  [CT.1]   CloudTrail multi-region enabled            - 12/50 accounts FAILED
  [IAM.4]  Root account has no access keys            -  3/50 accounts FAILED
  [EC2.19] Security groups restrict unrestricted ports- 31/50 accounts FAILED
  [RDS.3]  RDS encryption at rest enabled             - 18/50 accounts FAILED

FINDING SUMMARY:
  Total Active Findings: 1,247
  Critical: 34 | High: 189 | Medium: 567 | Low: 457
  Auto-Remediated This Month: 89
  Suppressed: 23
```
