---
name: auditing-aws-s3-bucket-permissions
description: >
  Systematically audit AWS S3 bucket permissions to identify publicly accessible buckets,
  overly permissive ACLs, misconfigured bucket policies, and missing encryption settings
  using AWS CLI, S3audit, and Prowler to enforce least-privilege data access controls.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, aws, s3, bucket-permissions, data-protection, access-control]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Auditing AWS S3 Bucket Permissions

## When to Use

- When conducting a security assessment of AWS environments to identify publicly exposed data
- When onboarding a new AWS account and establishing a security baseline for storage resources
- When responding to an alert about potential S3 data exposure from AWS Trusted Advisor or Security Hub
- When compliance frameworks (SOC 2, PCI DSS, HIPAA) require periodic review of data access controls
- When a breach or credential compromise necessitates immediate review of all accessible S3 resources

**Do not use** for auditing non-AWS object storage (use provider-specific tools), for real-time monitoring (use S3 Event Notifications with Lambda), or for auditing S3 access patterns (use S3 Access Analyzer or CloudTrail S3 data events).

## Prerequisites

- AWS CLI v2 configured with credentials that have `s3:GetBucketPolicy`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:GetEncryptionConfiguration`, and `s3:ListAllMyBuckets` permissions
- Prowler installed (`pip install prowler`) for automated CIS benchmark checks
- S3audit or similar enumeration tool for quick public bucket detection
- Access to AWS Organizations if auditing across multiple accounts
- Python 3.8+ with boto3 for custom audit scripts

## Workflow

### Step 1: Enumerate All S3 Buckets and Account-Level Block Public Access

Check the account-level S3 Block Public Access settings first, then list all buckets with their regions.

```bash
# Check account-level S3 Block Public Access settings
aws s3control get-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --output json

# List all buckets with creation dates
aws s3api list-buckets \
  --query 'Buckets[*].[Name,CreationDate]' \
  --output table

# Get bucket regions for each bucket
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  region=$(aws s3api get-bucket-location --bucket "$bucket" --query 'LocationConstraint' --output text)
  echo "$bucket -> ${region:-us-east-1}"
done
```

### Step 2: Check Each Bucket's Public Access Block and ACL Configuration

Iterate through all buckets to evaluate their individual public access blocks and ACL grants.

```bash
# Check per-bucket Block Public Access settings
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "=== $bucket ==="
  aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "  No Block Public Access configured"

  # Check ACL for public grants
  aws s3api get-bucket-acl --bucket "$bucket" \
    --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers` || Grantee.URI==`http://acs.amazonaws.com/groups/global/AuthenticatedUsers`]' \
    --output json
done
```

### Step 3: Analyze Bucket Policies for Overly Permissive Access

Review bucket policies for wildcard principals, missing conditions, and statements that allow broad access.

```bash
# Extract and analyze bucket policies
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  policy=$(aws s3api get-bucket-policy --bucket "$bucket" --output text 2>/dev/null)
  if [ -n "$policy" ]; then
    echo "=== $bucket policy ==="
    echo "$policy" | python3 -c "
import json, sys
policy = json.load(sys.stdin)
for stmt in policy.get('Statement', []):
    principal = stmt.get('Principal', {})
    effect = stmt.get('Effect', '')
    if principal == '*' or principal == {'AWS': '*'}:
        print(f'  WARNING: {effect} with wildcard principal')
        print(f'  Actions: {stmt.get(\"Action\", \"\")}')
        print(f'  Condition: {stmt.get(\"Condition\", \"NONE\")}')
"
  fi
done
```

### Step 4: Verify Encryption and Versioning Settings

Check that all buckets have server-side encryption enabled and versioning configured for data protection.

```bash
# Check encryption and versioning status for all buckets
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "=== $bucket ==="

  # Encryption configuration
  aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null \
    && echo "  Encryption: ENABLED" \
    || echo "  Encryption: DISABLED"

  # Versioning status
  aws s3api get-bucket-versioning --bucket "$bucket" \
    --query 'Status' --output text

  # Logging status
  aws s3api get-bucket-logging --bucket "$bucket" \
    --query 'LoggingEnabled' --output text 2>/dev/null
done
```

### Step 5: Run Prowler S3-Specific Checks

Execute Prowler's S3-focused checks aligned with CIS AWS Foundations Benchmark.

```bash
# Run Prowler S3-specific checks
prowler aws \
  --checks s3_bucket_public_access \
           s3_bucket_default_encryption \
           s3_bucket_policy_public_write_access \
           s3_bucket_server_access_logging_enabled \
           s3_bucket_versioning_enabled \
           s3_bucket_acl_prohibited \
  -M json-ocsf \
  -o ./prowler-s3-audit/

# View summary
prowler aws --checks s3 -M csv -o ./prowler-s3-audit/
```

### Step 6: Use IAM Access Analyzer for S3 Public and Cross-Account Findings

Leverage IAM Access Analyzer to identify buckets shared externally or publicly.

```bash
# List Access Analyzer findings for S3
aws accessanalyzer list-findings \
  --analyzer-arn $(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text) \
  --filter '{"resourceType": {"eq": ["AWS::S3::Bucket"]}}' \
  --query 'findings[*].[resource,status,condition,principal]' \
  --output table

# Create an analyzer if one does not exist
aws accessanalyzer create-analyzer \
  --analyzer-name s3-access-audit \
  --type ACCOUNT
```

### Step 7: Generate Audit Report and Remediate

Compile findings into an actionable report and apply remediation for critical issues.

```bash
# Quick remediation: Enable Block Public Access on a bucket
aws s3api put-public-access-block \
  --bucket TARGET_BUCKET \
  --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

# Enable default encryption with SSE-S3
aws s3api put-bucket-encryption \
  --bucket TARGET_BUCKET \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"alias/aws/s3"},"BucketKeyEnabled":true}]}'

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket TARGET_BUCKET \
  --versioning-configuration Status=Enabled
```

## Key Concepts

| Term | Definition |
|------|------------|
| S3 Block Public Access | Account-level and bucket-level settings that override ACLs and policies to prevent public access regardless of individual resource configurations |
| Bucket Policy | JSON-based resource policy attached to a bucket that defines who can access the bucket and what actions they can perform |
| ACL (Access Control List) | Legacy S3 access control mechanism granting permissions to AWS accounts or predefined groups like AllUsers or AuthenticatedUsers |
| IAM Access Analyzer | AWS service that analyzes resource policies to identify resources shared with external entities or the public |
| Server-Side Encryption | Encryption applied by S3 at the object level using SSE-S3, SSE-KMS, or SSE-C before writing data to disk |
| CIS AWS Foundations Benchmark | Security best practice standard from Center for Internet Security with specific controls for S3 bucket configuration |

## Tools & Systems

- **AWS CLI**: Primary interface for querying S3 bucket configurations, policies, ACLs, and encryption settings
- **Prowler**: Open-source security tool with 50+ S3-specific checks aligned to CIS, PCI DSS, and HIPAA controls
- **IAM Access Analyzer**: AWS-native service for continuous monitoring of resource policies that grant external access
- **S3audit**: Lightweight tool for quick enumeration of public S3 buckets across an account
- **ScoutSuite**: Multi-cloud auditing tool that collects S3 configuration data and generates risk-scored HTML reports

## Common Scenarios

### Scenario: Identifying a Publicly Readable Bucket Containing Customer Data

**Context**: A security engineer receives a Trusted Advisor alert about a publicly accessible S3 bucket. The bucket was created by a development team for a demo and was never locked down.

**Approach**:
1. Run `aws s3api get-bucket-acl` and find a grant to `AllUsers` with `READ` permission
2. Check `get-bucket-policy` and discover a policy with `Principal: "*"` and `s3:GetObject`
3. Confirm Block Public Access is not enabled at the bucket or account level
4. Enumerate bucket contents to assess data sensitivity
5. Immediately enable Block Public Access on the bucket
6. Review CloudTrail S3 data events to determine if unauthorized access occurred
7. Report the finding with timeline, data inventory, and remediation confirmation

**Pitfalls**: Enabling Block Public Access can break applications that intentionally serve content publicly (static websites). Always verify the bucket's intended use before applying restrictions. Check for CloudFront distributions or other services relying on the bucket's public access.

## Output Format

```
S3 Bucket Permissions Audit Report
=====================================
Account: 123456789012 (Production)
Date: 2026-02-23
Auditor: Security Engineering Team
Total Buckets: 47

ACCOUNT-LEVEL SETTINGS:
  Block Public Access: ENABLED (all four settings)

CRITICAL FINDINGS:
[S3-001] Public Read Access via ACL
  Bucket: marketing-assets-prod
  Issue: AllUsers group granted READ permission via ACL
  Risk: Any internet user can list and download bucket contents
  Data Sensitivity: Contains customer-facing but non-sensitive marketing assets
  Remediation: Remove AllUsers ACL grant, enable Block Public Access

[S3-002] Wildcard Principal in Bucket Policy
  Bucket: data-exchange-partner
  Issue: Policy allows s3:GetObject with Principal "*" and no VPC/IP condition
  Risk: Intended for partner access but accessible to anyone with the bucket name
  Remediation: Add aws:SourceVpce or aws:SourceIp condition to restrict access

SUMMARY:
  Buckets with public access:           3 / 47
  Buckets without encryption:           5 / 47
  Buckets without versioning:          12 / 47
  Buckets without access logging:      18 / 47
  Buckets with overly broad policies:   7 / 47
```
