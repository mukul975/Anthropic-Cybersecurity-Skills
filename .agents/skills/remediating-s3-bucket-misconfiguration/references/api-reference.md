# API Reference: S3 Bucket Misconfiguration Remediation Agent

## Overview

Audits and remediates S3 bucket security: public access blocks, bucket policies, ACLs, encryption, versioning, and access logging using boto3.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| boto3 | >= 1.28 | AWS S3 API for audit and remediation |

## Audit Functions

### `check_public_access_block(s3, bucket)`
Verifies all four S3 Block Public Access settings are enabled.
- **Returns**: `dict` with `block_config`, `fully_blocked`

### `check_bucket_policy(s3, bucket)`
Parses bucket policy for `Principal: "*"` Allow statements.
- **Returns**: `dict` with `public_statements` list (risk: CRITICAL)

### `check_bucket_acl(s3, bucket)`
Checks ACL grants for AllUsers or AuthenticatedUsers URIs.
- **Returns**: `dict` with `public_grants` list

### `check_encryption(s3, bucket)`
Checks for default server-side encryption configuration.
- **Returns**: `dict` with `encrypted`, `algorithm` (AES256 or aws:kms)

### `check_versioning(s3, bucket)`
Checks versioning status and MFA Delete configuration.
- **Returns**: `dict` with `status`, `mfa_delete`

### `check_logging(s3, bucket)`
Verifies access logging is enabled with target bucket.
- **Returns**: `dict` with `logging_enabled`, `target_bucket`

### `audit_all_buckets(s3)`
Full audit across all buckets, sorted by issue count.
- **Returns**: `list[dict]` with risk rating per bucket

## Remediation Functions

### `enable_public_access_block(s3, bucket)`
Enables all four S3 Block Public Access settings.

### `enable_encryption(s3, bucket, algorithm)`
Configures default SSE-KMS or AES256 encryption with bucket key.

### `enable_versioning(s3, bucket)`
Enables S3 versioning on the bucket.

## AWS API Calls

| API Call | Purpose |
|----------|---------|
| `list_buckets` | Enumerate all buckets |
| `get_public_access_block` | Check block config |
| `put_public_access_block` | Apply block config |
| `get_bucket_policy` | Read bucket policy |
| `get_bucket_acl` | Read ACL grants |
| `get_bucket_encryption` | Check encryption |
| `put_bucket_encryption` | Enable encryption |
| `get_bucket_versioning` | Check versioning |
| `put_bucket_versioning` | Enable versioning |
| `get_bucket_logging` | Check access logging |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | Yes | AWS credential |
| `AWS_SECRET_ACCESS_KEY` | Yes | AWS credential |
| `AWS_DEFAULT_REGION` | No | Default: us-east-1 |

## Usage

```bash
python agent.py us-east-1
```
