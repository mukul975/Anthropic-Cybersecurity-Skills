# API Reference: Cloud Penetration Testing Agent

## Overview

Enumerates AWS IAM users, roles, cross-account trusts, IMDSv1 instances, public S3 buckets, and Lambda secrets to identify privilege escalation paths and misconfigurations. For authorized penetration testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP API calls |
| AWS CLI | >=2.0 | AWS service enumeration (subprocess) |

## CLI Usage

```bash
python agent.py --profile target-account --output pentest_report.json
```

## Key Functions

### `enumerate_iam_users()`
Lists all IAM users with username, ARN, and creation date via `aws iam list-users`.

### `enumerate_iam_roles()`
Lists IAM roles and identifies cross-account trust relationships by inspecting AssumeRolePolicyDocument principals.

### `check_imds_v1_instances()`
Identifies running EC2 instances with IMDSv1 enabled (`HttpTokens: optional`), vulnerable to SSRF credential theft.

### `check_public_s3_buckets()`
Enumerates S3 buckets and checks each for public policy status via `get-bucket-policy-status`.

### `check_lambda_env_secrets()`
Inspects Lambda function environment variables for sensitive keys (password, secret, token, api_key).

### `test_privesc_create_policy_version(policy_arn)`
Tests if a policy allows `iam:CreatePolicyVersion` permission which enables privilege escalation.

## AWS CLI Commands Used

| Command | Purpose |
|---------|---------|
| `aws iam list-users` | Enumerate IAM users |
| `aws iam list-roles` | Enumerate roles and trust policies |
| `aws ec2 describe-instances` | Check IMDS configuration |
| `aws s3api list-buckets` | List S3 buckets |
| `aws s3api get-bucket-policy-status` | Check public access |
| `aws lambda list-functions` | Enumerate Lambda functions |
| `aws lambda get-function-configuration` | Inspect env vars |
| `aws iam simulate-principal-policy` | Test IAM permissions |

## MITRE ATT&CK Cloud Mapping

| Technique | ID | Function |
|-----------|----|----------|
| Cloud Account Discovery | T1087.004 | `enumerate_iam_users` |
| Steal Application Access Token | T1528 | `check_lambda_env_secrets` |
| Unsecured Credentials: Cloud Instance Metadata | T1552.005 | `check_imds_v1_instances` |
| Valid Accounts: Cloud Accounts | T1078.004 | `enumerate_iam_roles` |
