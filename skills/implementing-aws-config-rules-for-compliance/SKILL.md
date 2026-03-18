---
name: implementing-aws-config-rules-for-compliance
description: >
  Implementing AWS Config rules for continuous compliance monitoring of AWS resources,
  deploying managed and custom rules aligned to CIS and PCI DSS frameworks, configuring
  automatic remediation with SSM Automation, and aggregating compliance data across accounts.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, aws, config-rules, compliance, automation, remediation]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing AWS Config Rules for Compliance

## When to Use

- When establishing continuous compliance monitoring for AWS resources against regulatory standards
- When implementing automated detection and remediation of configuration drift
- When building a compliance dashboard across multiple AWS accounts using AWS Organizations
- When audit teams require evidence of continuous compliance rather than point-in-time assessments
- When deploying guardrails that detect non-compliant resources within minutes of creation

**Do not use** for real-time threat detection (use GuardDuty), for application vulnerability scanning (use Inspector), or for one-time compliance assessments (use Prowler for faster ad-hoc audits).

## Prerequisites

- AWS Config recording enabled in all target accounts and regions
- IAM role with `config:*`, `ssm:*`, and `lambda:*` permissions for rule management
- AWS Organizations with delegated administrator for Config aggregation
- S3 bucket for Config delivery channel and SNS topic for notifications
- CloudFormation StackSets or Terraform for multi-account rule deployment

## Workflow

### Step 1: Enable AWS Config Recording

Set up the Config recorder and delivery channel in each target account.

```bash
# Create S3 bucket for Config data
aws s3api create-bucket \
  --bucket config-compliance-data-ACCOUNT_ID \
  --region us-east-1

# Create Config service role
aws iam create-service-linked-role --aws-service-name config.amazonaws.com

# Start the Config recorder
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

# Set up delivery channel
aws configservice put-delivery-channel \
  --delivery-channel '{
    "name": "default",
    "s3BucketName": "config-compliance-data-ACCOUNT_ID",
    "snsTopicARN": "arn:aws:sns:us-east-1:ACCOUNT:config-notifications",
    "configSnapshotDeliveryProperties": {"deliveryFrequency": "TwentyFour_Hours"}
  }'

# Start recording
aws configservice start-configuration-recorder --configuration-recorder-name default
```

### Step 2: Deploy Managed Config Rules for CIS Compliance

Enable AWS-managed Config rules that map to CIS AWS Foundations Benchmark controls.

```bash
# S3 bucket security rules
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-ssl-requests-only",
  "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_SSL_REQUESTS_ONLY"}
}'

# IAM security rules
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "iam-root-access-key-check",
  "Source": {"Owner": "AWS", "SourceIdentifier": "IAM_ROOT_ACCESS_KEY_CHECK"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "mfa-enabled-for-iam-console-access",
  "Source": {"Owner": "AWS", "SourceIdentifier": "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "iam-password-policy",
  "Source": {"Owner": "AWS", "SourceIdentifier": "IAM_PASSWORD_POLICY"},
  "InputParameters": "{\"RequireUppercaseCharacters\":\"true\",\"RequireLowercaseCharacters\":\"true\",\"RequireSymbols\":\"true\",\"RequireNumbers\":\"true\",\"MinimumPasswordLength\":\"14\"}"
}'

# Network security rules
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "restricted-ssh",
  "Source": {"Owner": "AWS", "SourceIdentifier": "INCOMING_SSH_DISABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "vpc-flow-logs-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "VPC_FLOW_LOGS_ENABLED"}
}'

# Encryption rules
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "rds-storage-encrypted",
  "Source": {"Owner": "AWS", "SourceIdentifier": "RDS_STORAGE_ENCRYPTED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "encrypted-volumes",
  "Source": {"Owner": "AWS", "SourceIdentifier": "ENCRYPTED_VOLUMES"}
}'
```

### Step 3: Create Custom Config Rules with Lambda

Build custom rules for organization-specific compliance requirements.

```python
# custom_config_rule.py - Ensure EC2 instances have required tags
import json
import boto3

config = boto3.client('config')

REQUIRED_TAGS = ['Environment', 'Owner', 'CostCenter', 'Project']

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event.get('configurationItem', {})

    if configuration_item['resourceType'] != 'AWS::EC2::Instance':
        return

    tags = {t['key']: t['value'] for t in configuration_item.get('tags', [])}
    missing_tags = [tag for tag in REQUIRED_TAGS if tag not in tags]

    if missing_tags:
        compliance = 'NON_COMPLIANT'
        annotation = f"Missing required tags: {', '.join(missing_tags)}"
    else:
        compliance = 'COMPLIANT'
        annotation = 'All required tags present'

    config.put_evaluations(
        Evaluations=[{
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': configuration_item['resourceId'],
            'ComplianceType': compliance,
            'Annotation': annotation,
            'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
        }],
        ResultToken=event['resultToken']
    )
```

```bash
# Deploy the custom rule
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "ec2-required-tags",
  "Source": {
    "Owner": "CUSTOM_LAMBDA",
    "SourceIdentifier": "arn:aws:lambda:us-east-1:ACCOUNT:function:config-required-tags",
    "SourceDetails": [{
      "EventSource": "aws.config",
      "MessageType": "ConfigurationItemChangeNotification"
    }]
  },
  "Scope": {"ComplianceResourceTypes": ["AWS::EC2::Instance"]}
}'
```

### Step 4: Configure Automatic Remediation

Set up SSM Automation documents for automatic remediation of non-compliant resources.

```bash
# Auto-remediate public S3 buckets
aws configservice put-remediation-configurations --remediation-configurations '[{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "TargetType": "SSM_DOCUMENT",
  "TargetId": "AWS-DisableS3BucketPublicReadWrite",
  "Parameters": {
    "S3BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}},
    "AutomationAssumeRole": {"StaticValue": {"Values": ["arn:aws:iam::ACCOUNT:role/ConfigRemediationRole"]}}
  },
  "Automatic": true,
  "MaximumAutomaticAttempts": 3,
  "RetryAttemptSeconds": 60
}]'

# Auto-remediate unencrypted EBS volumes
aws configservice put-remediation-configurations --remediation-configurations '[{
  "ConfigRuleName": "encrypted-volumes",
  "TargetType": "SSM_DOCUMENT",
  "TargetId": "AWS-EnableEBSEncryptionByDefault",
  "Parameters": {
    "AutomationAssumeRole": {"StaticValue": {"Values": ["arn:aws:iam::ACCOUNT:role/ConfigRemediationRole"]}}
  },
  "Automatic": true,
  "MaximumAutomaticAttempts": 1,
  "RetryAttemptSeconds": 300
}]'

# Auto-remediate security groups allowing SSH from 0.0.0.0/0
aws configservice put-remediation-configurations --remediation-configurations '[{
  "ConfigRuleName": "restricted-ssh",
  "TargetType": "SSM_DOCUMENT",
  "TargetId": "AWS-DisablePublicAccessForSecurityGroup",
  "Parameters": {
    "GroupId": {"ResourceValue": {"Value": "RESOURCE_ID"}},
    "AutomationAssumeRole": {"StaticValue": {"Values": ["arn:aws:iam::ACCOUNT:role/ConfigRemediationRole"]}}
  },
  "Automatic": true,
  "MaximumAutomaticAttempts": 3,
  "RetryAttemptSeconds": 60
}]'
```

### Step 5: Set Up Multi-Account Aggregation

Aggregate compliance data from all organization accounts into a central view.

```bash
# Create a Config aggregator for the organization
aws configservice put-configuration-aggregator \
  --configuration-aggregator-name org-compliance-aggregator \
  --organization-aggregation-source '{
    "RoleArn": "arn:aws:iam::ACCOUNT:role/ConfigAggregatorRole",
    "AllAwsRegions": true
  }'

# Query aggregate compliance across all accounts
aws configservice get-aggregate-compliance-details-by-config-rule \
  --configuration-aggregator-name org-compliance-aggregator \
  --config-rule-name s3-bucket-public-read-prohibited \
  --compliance-type NON_COMPLIANT \
  --query 'AggregateEvaluationResults[*].[AccountId,AwsRegion,EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,ComplianceType]' \
  --output table

# Get compliance summary by account
aws configservice get-aggregate-compliance-summary-by-source \
  --configuration-aggregator-name org-compliance-aggregator \
  --query 'AggregateComplianceCounts[*].[GroupName,ComplianceSummary.CompliantResourceCount.CappedCount,ComplianceSummary.NonCompliantResourceCount.CappedCount]' \
  --output table
```

## Key Concepts

| Term | Definition |
|------|------------|
| AWS Config Rule | A compliance check that evaluates whether AWS resource configurations meet specified requirements, either continuously or on a schedule |
| Managed Rule | AWS-provided pre-built Config rule with standardized logic for common compliance checks like encryption and public access |
| Custom Rule | Organization-specific Config rule backed by a Lambda function that evaluates custom compliance logic |
| Remediation Action | SSM Automation document or Lambda function triggered to automatically fix non-compliant resources |
| Configuration Aggregator | AWS Config feature that collects compliance data from multiple accounts and regions into a centralized view |
| Conformance Pack | Collection of Config rules and remediation actions packaged as a deployable unit for specific compliance frameworks |

## Tools & Systems

- **AWS Config**: Continuous configuration recording and compliance evaluation service for AWS resources
- **SSM Automation**: AWS Systems Manager documents for executing automated remediation actions on non-compliant resources
- **Config Conformance Packs**: Pre-built rule collections for CIS, PCI DSS, NIST 800-53, and HIPAA compliance
- **CloudFormation StackSets**: Multi-account deployment mechanism for Config rules across AWS Organizations
- **Config Aggregator**: Cross-account and cross-region compliance data consolidation

## Common Scenarios

### Scenario: Deploying CIS Compliance Monitoring Across 30 AWS Accounts

**Context**: A financial services company needs to demonstrate continuous CIS AWS Foundations Benchmark compliance across all 30 production accounts for their annual SOC 2 audit.

**Approach**:
1. Enable AWS Config recording in all accounts via CloudFormation StackSets
2. Deploy the CIS conformance pack to all accounts using StackSets
3. Set up a Config aggregator in the security account for organization-wide visibility
4. Configure auto-remediation for safe-to-fix rules (public S3, unencrypted volumes)
5. Create EventBridge rules to alert on new NON_COMPLIANT evaluations
6. Build a weekly compliance report aggregating scores across all accounts
7. Store Config snapshots in S3 with lifecycle policies for audit retention

**Pitfalls**: Config recording incurs costs per configuration item recorded. In accounts with many resources, costs can be significant. Use targeted recording groups to focus on compliance-relevant resource types rather than recording all resources. Auto-remediation of network rules (security groups) can disrupt applications if the rule was intentionally permissive.

## Output Format

```
AWS Config Compliance Report
===============================
Organization: Acme Financial (30 accounts)
Framework: CIS AWS Foundations 1.4
Report Date: 2026-02-23
Config Rules Active: 48

COMPLIANCE SUMMARY:
  Overall Compliance: 87%
  Compliant Resources:     4,234
  Non-Compliant Resources:   612
  Not Applicable:            189

TOP NON-COMPLIANT RULES:
  encrypted-volumes:              89 resources (14 accounts)
  vpc-flow-logs-enabled:          67 resources (12 accounts)
  mfa-enabled-for-iam-console:    45 resources (8 accounts)
  s3-bucket-ssl-requests-only:    34 resources (6 accounts)
  restricted-ssh:                 28 resources (5 accounts)

AUTO-REMEDIATION (Last 30 Days):
  Public S3 buckets remediated:    12
  Security groups restricted:       8
  EBS default encryption enabled:   6
  Total auto-remediated:           26
  Failed remediation attempts:      3

ACCOUNT COMPLIANCE RANKING:
  1. prod-core (account-001):     96% compliant
  2. prod-data (account-002):     94% compliant
  ...
  30. dev-sandbox (account-030):  68% compliant
```
