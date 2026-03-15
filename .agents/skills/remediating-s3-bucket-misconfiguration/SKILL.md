---
name: remediating-s3-bucket-misconfiguration
description: >
  This skill provides step-by-step procedures for identifying and remediating Amazon S3
  bucket misconfigurations that expose sensitive data to unauthorized access. It covers
  enabling S3 Block Public Access at account and bucket levels, auditing bucket policies
  and ACLs, enforcing encryption, configuring access logging, and deploying automated
  remediation using AWS Config and Lambda.
domain: cybersecurity
subdomain: cloud-security
tags: [s3-security, bucket-misconfiguration, data-exposure, public-access-block, aws-config]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Remediating S3 Bucket Misconfiguration

## When to Use

- When AWS Config or Security Hub reports S3 buckets with public access or missing encryption
- When a security scan reveals S3 bucket policies granting access to Principal "*" (everyone)
- When preparing for a data protection audit requiring evidence of storage security controls
- When responding to a data exposure incident involving publicly accessible S3 objects
- When establishing preventive controls for new S3 bucket creation across an AWS Organization

**Do not use** for Azure Blob Storage or GCP Cloud Storage misconfigurations, for S3 data classification (see implementing-cloud-dlp-policy), or for S3 access pattern analysis unrelated to security.

## Prerequisites

- AWS account with S3 administrative permissions (s3:*, s3-outposts:*)
- AWS Config enabled to evaluate S3 resource compliance
- AWS CloudTrail logging S3 data events for access auditing
- Macie enabled for sensitive data discovery in S3 buckets

## Workflow

### Step 1: Identify All Public and Misconfigured Buckets

Use multiple detection methods to identify S3 buckets with public access. Rely on AWS Config rules, S3 Access Analyzer, and Macie rather than manual inspection.

```bash
# Enable S3 Access Analyzer for external access detection
aws accessanalyzer create-analyzer \
  --analyzer-name s3-analyzer \
  --type ACCOUNT

# List all S3 buckets with public access indicators
aws s3api list-buckets --query 'Buckets[*].Name' --output text | while read bucket; do
  public_status=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
  if [ $? -ne 0 ]; then
    echo "NO PUBLIC ACCESS BLOCK: $bucket"
  fi
done

# Check bucket policies for public access grants
aws s3api list-buckets --query 'Buckets[*].Name' --output text | while read bucket; do
  policy=$(aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null)
  if echo "$policy" | grep -q '"Principal":"*"' 2>/dev/null; then
    echo "PUBLIC POLICY DETECTED: $bucket"
  fi
done

# Use AWS Config to find non-compliant buckets
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited \
  --compliance-types NON_COMPLIANT \
  --query 'EvaluationResults[*].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId'
```

### Step 2: Enable S3 Block Public Access at Account Level

Apply the four Block Public Access settings at the AWS account level as a safety net. This prevents any bucket in the account from being made public, regardless of individual bucket policies or ACLs.

```bash
# Enable account-level Block Public Access (all four settings)
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'

# Verify account-level settings
aws s3control get-public-access-block --account-id 123456789012

# Enable at bucket level for defense in depth
aws s3api put-public-access-block \
  --bucket production-data-bucket \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
```

### Step 3: Audit and Remediate Bucket Policies and ACLs

Review all bucket policies for overly permissive Principal statements and remove legacy ACLs. Enforce bucket ownership controls to disable ACLs entirely.

```bash
# Remove a public bucket policy
aws s3api delete-bucket-policy --bucket exposed-bucket

# Replace with a restrictive policy
aws s3api put-bucket-policy --bucket exposed-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::exposed-bucket",
        "arn:aws:s3:::exposed-bucket/*"
      ],
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    },
    {
      "Sid": "AllowOnlyVPCEndpoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::exposed-bucket",
        "arn:aws:s3:::exposed-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {"aws:SourceVpce": "vpce-0abc123def456"}
      }
    }
  ]
}'

# Enforce bucket owner for all objects (disable ACLs)
aws s3api put-bucket-ownership-controls --bucket exposed-bucket \
  --ownership-controls '{"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}'
```

### Step 4: Enforce Default Encryption

Enable default server-side encryption with AWS KMS or AES-256 for all buckets. Add a bucket policy denying unencrypted object uploads.

```bash
# Enable default KMS encryption
aws s3api put-bucket-encryption --bucket production-data-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/key-id"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Deny unencrypted uploads via bucket policy
aws s3api put-bucket-policy --bucket production-data-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedUploads",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::production-data-bucket/*",
    "Condition": {
      "StringNotEquals": {"s3:x-amz-server-side-encryption": ["aws:kms", "AES256"]}
    }
  }]
}'
```

### Step 5: Enable Access Logging and Monitoring

Configure S3 server access logging and CloudTrail data events to track all object-level operations. Set up EventBridge rules to alert on suspicious access patterns.

```bash
# Enable server access logging
aws s3api put-bucket-logging --bucket production-data-bucket \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "s3-access-logs-bucket",
      "TargetPrefix": "production-data-bucket/"
    }
  }'

# Enable CloudTrail S3 data events
aws cloudtrail put-event-selectors --trail-name management-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::production-data-bucket/"]
    }]
  }]'
```

### Step 6: Deploy Preventive Controls with SCP and Config

Use Service Control Policies to prevent disabling Block Public Access across the organization. Deploy AWS Config rules with auto-remediation.

```bash
# SCP preventing Block Public Access removal
aws organizations create-policy \
  --name PreventS3PublicAccess \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyRemovePublicAccessBlock",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/SecurityAdmin"}
      }
    }]
  }'
```

## Key Concepts

| Term | Definition |
|------|------------|
| S3 Block Public Access | Four account-level and bucket-level settings that override any policy or ACL granting public access to S3 resources |
| Bucket Policy | JSON-based resource policy attached to an S3 bucket defining who can access what objects under which conditions |
| ACL (Access Control List) | Legacy S3 access mechanism that grants permissions at the bucket or object level; should be disabled via BucketOwnerEnforced |
| BucketOwnerEnforced | Ownership control setting that disables all ACLs on a bucket, making the bucket owner the sole authority for access control |
| Server-Side Encryption | Automatic encryption of objects at rest using AES-256 (SSE-S3), AWS KMS (SSE-KMS), or customer-provided keys (SSE-C) |
| VPC Endpoint | Private connection between a VPC and S3 that restricts bucket access to traffic originating from within the VPC |
| S3 Access Analyzer | IAM Access Analyzer capability that identifies S3 buckets shared with external entities outside the account or organization |

## Tools & Systems

- **AWS Config**: Evaluates S3 bucket compliance against managed rules and triggers auto-remediation for non-compliant resources
- **Amazon Macie**: Discovers and classifies sensitive data in S3 buckets to identify which misconfigurations pose the highest data exposure risk
- **IAM Access Analyzer**: Identifies S3 buckets with policies or ACLs that grant access to external principals
- **S3 Storage Lens**: Provides organization-wide visibility into S3 usage patterns, access metrics, and security anomalies
- **Prowler**: Open-source tool that checks S3 security configurations against CIS benchmarks and best practices

## Common Scenarios

### Scenario: Data Breach from Publicly Readable S3 Bucket Containing PII

**Context**: A security researcher reports that an S3 bucket containing 273,000 bank transfer PDFs is publicly readable. The bucket was created by a developer who needed to share files with an external partner and set the ACL to public-read.

**Approach**:
1. Immediately enable Block Public Access on the specific bucket to stop the exposure
2. Revoke all public ACLs by setting BucketOwnerEnforced ownership controls
3. Audit CloudTrail and S3 access logs to determine which IP addresses accessed the exposed objects
4. Run Macie on the bucket to classify the types of PII exposed and assess regulatory notification requirements
5. Enable account-level Block Public Access to prevent recurrence across all buckets
6. Deploy an SCP preventing any principal except SecurityAdmin from modifying Block Public Access settings
7. Create a pre-signed URL mechanism or S3 Access Point for the legitimate partner sharing use case

**Pitfalls**: Enabling Block Public Access without notifying the team that set up the public access breaks their workflow. Not running access log analysis before remediation loses evidence of who accessed the exposed data.

## Output Format

```
S3 Bucket Security Remediation Report
=======================================
Account: 123456789012
Assessment Date: 2025-02-23
Buckets Scanned: 156

ACCOUNT-LEVEL CONTROLS:
  Block Public Access: ENABLED (all four settings)
  SCP Preventing Removal: DEPLOYED

CRITICAL FINDINGS (Remediated):
  [S3-001] production-uploads - Public READ via ACL
    Status: REMEDIATED - BucketOwnerEnforced applied
    Objects Exposed: 273,412
    Duration of Exposure: 47 days
    Unique External IPs Accessed: 1,247

  [S3-002] analytics-export - Public bucket policy (Principal: *)
    Status: REMEDIATED - Policy replaced with VPC endpoint restriction
    Sensitive Data (Macie): 12,400 objects with PII detected

HIGH FINDINGS:
  [S3-003] 14 buckets missing default encryption
    Status: REMEDIATED - KMS encryption enabled
  [S3-004] 8 buckets without server access logging
    Status: REMEDIATED - Logging enabled to centralized log bucket

SUMMARY:
  Buckets Remediated: 24/156
  Encryption Coverage: 100%
  Access Logging Coverage: 100%
  Block Public Access: 156/156 buckets
```
