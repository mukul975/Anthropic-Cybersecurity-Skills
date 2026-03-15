# AWS IAM Privilege Escalation Detection API Reference

## boto3 IAM API

```python
import boto3

iam = boto3.client("iam")

# Download full account authorization details
paginator = iam.get_paginator("get_account_authorization_details")
for page in paginator.paginate():
    users = page["UserDetailList"]
    roles = page["RoleDetailList"]
    policies = page["Policies"]

# Get specific policy version
policy = iam.get_policy_version(
    PolicyArn="arn:aws:iam::123456789012:policy/MyPolicy",
    VersionId="v2"
)
```

## Cloudsplaining CLI

```bash
# Install
pip install cloudsplaining

# Download account authorization details
cloudsplaining download --profile myprofile

# Scan authorization file for privilege escalation
cloudsplaining scan --input-file default.json --output results/

# Scan a single policy file
cloudsplaining scan-policy-file --input-file policy.json
```

## Known Privilege Escalation Vectors

| Vector | Required Permissions | Risk |
|--------|---------------------|------|
| CreatePolicyVersion | `iam:CreatePolicyVersion` | Critical |
| AttachUserPolicy | `iam:AttachUserPolicy` | Critical |
| PutUserPolicy | `iam:PutUserPolicy` | Critical |
| PassRole + Lambda | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` | Critical |
| PassRole + EC2 | `iam:PassRole`, `ec2:RunInstances` | Critical |
| UpdateAssumeRolePolicy | `iam:UpdateAssumeRolePolicy` | Critical |
| PassRole + CloudFormation | `iam:PassRole`, `cloudformation:CreateStack` | High |
| PassRole + SSM | `iam:PassRole`, `ssm:SendCommand` | Critical |

## AWS CLI IAM Audit Commands

```bash
# List all users with attached policies
aws iam list-users --output json

# Get user's inline policies
aws iam list-user-policies --user-name admin

# Get attached managed policies
aws iam list-attached-user-policies --user-name admin

# Simulate policy evaluation
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/admin \
  --action-names iam:CreatePolicyVersion iam:AttachUserPolicy

# Get account authorization details (full dump)
aws iam get-account-authorization-details > auth-details.json
```

## Parliament (Policy Linting)

```bash
pip install parliament
parliament --file policy.json
```
