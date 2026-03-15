---
name: implementing-aws-security-hub-compliance
description: >
  Implementing AWS Security Hub to aggregate security findings across AWS accounts, enable
  compliance standards like CIS AWS Foundations and PCI DSS, configure automated remediation
  with EventBridge and Lambda, and create custom security insights for organizational risk management.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, aws, security-hub, compliance, cspm, cis-benchmark]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing AWS Security Hub Compliance

## When to Use

- When establishing centralized security posture management across multiple AWS accounts
- When compliance requirements demand continuous monitoring against CIS, PCI DSS, or NIST 800-53 standards
- When aggregating findings from GuardDuty, Inspector, Macie, Firewall Manager, and third-party tools
- When building automated remediation workflows triggered by security findings
- When executive stakeholders require a security compliance dashboard across the organization

**Do not use** for real-time threat detection (use GuardDuty), for vulnerability scanning (use Inspector), or for data classification (use Macie). Security Hub aggregates findings from these services but does not replace them.

## Prerequisites

- AWS Organizations with delegated administrator for Security Hub
- IAM permissions for `securityhub:*`, `config:*`, `events:*`, and `lambda:*`
- AWS Config enabled in all target accounts and regions (required by Security Hub)
- CloudFormation StackSets or Terraform for multi-account deployment
- SNS topics configured for alert routing to security team

## Workflow

### Step 1: Enable Security Hub with Compliance Standards

Enable Security Hub in the management account and select compliance standards to evaluate.

```bash
# Enable Security Hub in the current account/region
aws securityhub enable-security-hub \
  --enable-default-standards \
  --control-finding-generator SECURITY_CONTROL

# Enable specific compliance standards
aws securityhub batch-enable-standards --standards-subscription-requests \
  '[
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0"}
  ]'

# Verify enabled standards
aws securityhub get-enabled-standards \
  --query 'StandardsSubscriptions[*].[StandardsArn,StandardsStatus]' --output table
```

### Step 2: Configure Multi-Account Aggregation

Set up a delegated administrator and aggregate findings from all organization accounts.

```bash
# Designate a delegated admin (run from management account)
aws securityhub enable-organization-admin-account \
  --admin-account-id 111122223333

# From the delegated admin account, enable auto-enrollment
aws securityhub update-organization-configuration \
  --auto-enable \
  --auto-enable-standards DEFAULT

# Create a finding aggregator for cross-region aggregation
aws securityhub create-finding-aggregator \
  --region-linking-mode ALL_REGIONS

# List member accounts
aws securityhub list-members \
  --query 'Members[*].[AccountId,MemberStatus]' --output table
```

### Step 3: Review Compliance Scores and Failed Controls

Query Security Hub for compliance posture across enabled standards and identify failing controls.

```bash
# Get overall compliance score for CIS benchmark
aws securityhub get-standards-control-associations \
  --security-control-id "IAM.1" \
  --query 'StandardsControlAssociationSummaries[*].[StandardsArn,AssociationStatus]' \
  --output table

# List all failed controls
aws securityhub get-findings \
  --filters '{
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]
  }' \
  --sort-criteria '{"Field": "SeverityNormalized", "SortOrder": "desc"}' \
  --max-items 50 \
  --query 'Findings[*].[Title,Severity.Label,Compliance.Status,Resources[0].Id]' \
  --output table

# Get finding counts by severity
aws securityhub get-insight-results \
  --insight-arn "arn:aws:securityhub:us-east-1:111122223333:insight/111122223333/default/2"
```

### Step 4: Create Custom Security Insights

Build custom insights to track organization-specific security priorities.

```bash
# Create insight for publicly accessible resources
aws securityhub create-insight \
  --name "Publicly Accessible Resources" \
  --filters '{
    "ResourceType": [
      {"Value": "AwsS3Bucket", "Comparison": "EQUALS"},
      {"Value": "AwsEc2SecurityGroup", "Comparison": "EQUALS"},
      {"Value": "AwsRdsDbInstance", "Comparison": "EQUALS"}
    ],
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}, {"Value": "HIGH", "Comparison": "EQUALS"}]
  }' \
  --group-by-attribute "ResourceType"

# Create insight for unencrypted resources
aws securityhub create-insight \
  --name "Unencrypted Resources Across Accounts" \
  --filters '{
    "Title": [{"Value": "encryption", "Comparison": "CONTAINS"}],
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}]
  }' \
  --group-by-attribute "AwsAccountId"
```

### Step 5: Configure Automated Remediation with EventBridge

Set up EventBridge rules to trigger Lambda-based auto-remediation for specific finding types.

```bash
# Create EventBridge rule for Security Hub findings
aws events put-rule \
  --name "security-hub-critical-findings" \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Severity": {"Label": ["CRITICAL"]},
        "Compliance": {"Status": ["FAILED"]},
        "Workflow": {"Status": ["NEW"]}
      }
    }
  }'

# Example Lambda auto-remediation for S3 public access (Python)
cat > /tmp/remediate_s3.py << 'PYEOF'
import boto3
import json

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    securityhub = boto3.client('securityhub')

    for finding in event['detail']['findings']:
        if 'S3' in finding.get('Title', '') and 'public' in finding.get('Title', '').lower():
            bucket_arn = finding['Resources'][0]['Id']
            bucket_name = bucket_arn.split(':::')[-1]

            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )

            securityhub.batch_update_findings(
                FindingIdentifiers=[{
                    'Id': finding['Id'],
                    'ProductArn': finding['ProductArn']
                }],
                Workflow={'Status': 'RESOLVED'},
                Note={
                    'Text': 'Auto-remediated: Block Public Access enabled',
                    'UpdatedBy': 'security-hub-auto-remediation'
                }
            )
    return {'statusCode': 200}
PYEOF
```

### Step 6: Export Findings and Generate Compliance Reports

Export Security Hub findings for reporting and integration with external SIEM or GRC platforms.

```bash
# Export all findings to S3 via a custom script
aws securityhub get-findings \
  --filters '{
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --max-items 1000 \
  --output json > security-hub-findings-export.json

# Send critical findings to SNS
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:111122223333:security-alerts \
  --subject "Security Hub Daily Summary" \
  --message file://daily-summary.json

# Integrate with third-party SIEM via EventBridge
aws events put-targets \
  --rule security-hub-critical-findings \
  --targets '[{
    "Id": "splunk-hec",
    "Arn": "arn:aws:events:us-east-1:111122223333:api-destination/splunk-hec",
    "HttpParameters": {
      "HeaderParameters": {"Authorization": "Splunk HEC_TOKEN"}
    }
  }]'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Security Hub | AWS service that aggregates security findings from AWS services and third-party tools, evaluates compliance against standards, and provides a unified security dashboard |
| Security Standard | A predefined set of security controls (CIS, PCI DSS, NIST 800-53) that Security Hub evaluates against your AWS configuration |
| Security Control | An individual check within a standard that evaluates a specific AWS resource configuration, such as whether S3 buckets block public access |
| Finding | A security issue detected by Security Hub or an integrated service, formatted in AWS Security Finding Format (ASFF) |
| Insight | A custom or managed grouping of findings by a specific attribute, providing aggregated views for security analysis |
| ASFF | AWS Security Finding Format, the standardized JSON schema used by all Security Hub integrations for consistent finding representation |

## Tools & Systems

- **AWS Security Hub**: Central aggregation and compliance evaluation platform for security findings across AWS accounts
- **AWS Config**: Configuration recording service required by Security Hub for evaluating resource compliance
- **Amazon EventBridge**: Event bus for routing Security Hub findings to Lambda, SNS, or external remediation systems
- **AWS Lambda**: Serverless compute for automated remediation functions triggered by Security Hub findings
- **Prowler**: Open-source tool that can send findings to Security Hub via ASFF integration

## Common Scenarios

### Scenario: Rolling Out Security Hub Across a 50-Account Organization

**Context**: A security team needs to enable Security Hub with CIS and FSBP standards across all accounts in an AWS Organization, with centralized finding aggregation and automated alerting.

**Approach**:
1. Enable Security Hub in the management account and designate a security account as delegated admin
2. Configure auto-enable for all existing and new member accounts via `update-organization-configuration`
3. Create a cross-region finding aggregator to consolidate findings from all regions into the admin account
4. Enable CIS AWS Foundations 1.4 and AWS FSBP standards across all accounts
5. Create EventBridge rules to route CRITICAL findings to PagerDuty and all findings to Splunk
6. Build custom insights for the top organizational risks: public resources, missing encryption, unused credentials
7. Schedule weekly compliance reports to stakeholders using Lambda and SES

**Pitfalls**: Security Hub requires AWS Config to be enabled in every account and region. Failing to enable Config will result in controls showing as "No data" rather than PASSED or FAILED. Member accounts with Config disabled will silently produce incomplete compliance scores.

## Output Format

```
AWS Security Hub Compliance Report
=====================================
Organization: acme-corp (50 accounts)
Region: us-east-1 (aggregated from all regions)
Report Date: 2026-02-23
Standards Enabled: CIS 1.4, FSBP v1.0, PCI DSS 3.2.1

COMPLIANCE SCORES:
  CIS AWS Foundations 1.4:     78% (142/182 controls passing)
  AWS FSBP v1.0.0:             85% (198/233 controls passing)
  PCI DSS 3.2.1:               72% (89/124 controls passing)

CRITICAL FINDINGS: 23
HIGH FINDINGS: 87
MEDIUM FINDINGS: 245
LOW FINDINGS: 412

TOP FAILING CONTROLS:
  [IAM.6]  MFA not enabled for root account           12 accounts
  [S3.2]   S3 Block Public Access not enabled          8 accounts
  [EC2.19] Security groups allow unrestricted access   15 accounts
  [RDS.3]  RDS encryption at rest not enabled          6 accounts

AUTO-REMEDIATION ACTIONS (Last 30 Days):
  S3 Block Public Access enabled:    14
  Security Group rules restricted:    8
  CloudTrail logging re-enabled:      3
  Total auto-remediated findings:    25
```
