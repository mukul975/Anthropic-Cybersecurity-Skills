---
name: securing-aws-iam-permissions
description: >
  This skill guides practitioners through hardening AWS Identity and Access Management
  configurations to enforce least privilege access across cloud accounts. It covers IAM
  policy scoping, permission boundaries, Access Analyzer integration, and credential
  rotation strategies to reduce the blast radius of compromised identities.
domain: cybersecurity
subdomain: cloud-security
tags: [aws-iam, least-privilege, permission-boundaries, access-analyzer, cloud-identity]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Securing AWS IAM Permissions

## When to Use

- When onboarding new AWS accounts or workloads that require scoped IAM policies
- When IAM Access Analyzer reports overly permissive policies or unused permissions
- When preparing for a compliance audit requiring least privilege evidence (SOC 2, PCI-DSS)
- When migrating from long-lived access keys to short-lived role-based credentials
- When remediating findings from AWS Security Hub related to IAM misconfigurations

**Do not use** for Azure AD or Google Cloud IAM configurations, application-level authorization logic, or federated identity provider setup (see managing-cloud-identity-with-okta).

## Prerequisites

- AWS account with administrative access or IAM:FullAccess permissions
- AWS CLI v2 installed and configured with named profiles
- AWS CloudTrail enabled for at least 90 days of API activity history
- Familiarity with JSON-based IAM policy syntax and ARN resource notation

## Workflow

### Step 1: Inventory Existing IAM Entities and Policies

Generate a comprehensive inventory of all IAM users, roles, groups, and attached policies using the AWS CLI and IAM credential reports. Identify accounts with console access, programmatic access keys, and their last-used timestamps.

```bash
# Generate IAM credential report
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d > iam-report.csv

# List all IAM roles and their attached policies
aws iam list-roles --query 'Roles[*].[RoleName,Arn,CreateDate]' --output table

# Find users with access keys older than 90 days
aws iam list-users --query 'Users[*].UserName' --output text | while read user; do
  aws iam list-access-keys --user-name "$user" \
    --query "AccessKeyMetadata[?CreateDate<='$(date -d '-90 days' +%Y-%m-%d)'].[UserName,AccessKeyId,Status,CreateDate]" \
    --output table
done
```

### Step 2: Enable and Analyze IAM Access Analyzer Findings

Activate IAM Access Analyzer at the organization or account level to identify resources shared externally and generate least-privilege policy recommendations based on CloudTrail activity.

```bash
# Create an Access Analyzer for the account
aws accessanalyzer create-analyzer \
  --analyzer-name account-analyzer \
  --type ACCOUNT

# List active findings for external access
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/account-analyzer \
  --filter '{"status": {"eq": ["ACTIVE"]}}'

# Generate a policy based on CloudTrail activity for a specific role
aws accessanalyzer start-policy-generation \
  --policy-generation-details '{
    "principalArn": "arn:aws:iam::123456789012:role/AppRole",
    "cloudTrailDetails": {
      "trailArn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
      "startTime": "2025-01-01T00:00:00Z",
      "endTime": "2025-03-01T00:00:00Z"
    }
  }'
```

### Step 3: Scope Policies to Specific Resources and Conditions

Replace wildcard resource ARNs with specific resource identifiers. Add IAM policy conditions for MFA enforcement, source IP restrictions, and time-based access windows.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadSpecificBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::production-data-bucket",
        "arn:aws:s3:::production-data-bucket/*"
      ],
      "Condition": {
        "Bool": {"aws:MultiFactorAuthPresent": "true"},
        "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
        "DateGreaterThan": {"aws:CurrentTime": "2025-01-01T00:00:00Z"}
      }
    }
  ]
}
```

### Step 4: Implement Permission Boundaries

Attach permission boundaries to IAM roles and users to define the maximum scope of permissions an entity can receive, preventing privilege escalation even if an administrator attaches an overly permissive policy.

```bash
# Create a permission boundary policy
aws iam create-policy \
  --policy-name DeveloperPermissionBoundary \
  --policy-document file://developer-boundary.json

# Attach the boundary to an IAM role
aws iam put-role-permissions-boundary \
  --role-name DeveloperRole \
  --permissions-boundary "arn:aws:iam::123456789012:policy/DeveloperPermissionBoundary"
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCommonServices",
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "dynamodb:*",
        "lambda:*",
        "logs:*",
        "cloudwatch:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyIAMChanges",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePermissionsBoundary"
      ],
      "Resource": "*"
    }
  ]
}
```

### Step 5: Enforce MFA and Eliminate Long-Lived Credentials

Require MFA for all human users accessing the AWS console and CLI. Migrate workloads from IAM user access keys to IAM roles with temporary credentials via STS AssumeRole.

```bash
# Enforce MFA via SCP at the organization level
aws organizations create-policy \
  --name RequireMFA \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyAllExceptMFA",
        "Effect": "Deny",
        "NotAction": [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ],
        "Resource": "*",
        "Condition": {
          "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
        }
      }
    ]
  }'

# Deactivate unused access keys
aws iam update-access-key --user-name old-user --access-key-id AKIAEXAMPLE --status Inactive
```

### Step 6: Automate Continuous IAM Monitoring

Deploy AWS Config rules and Security Hub controls to continuously evaluate IAM posture. Set up EventBridge rules to alert on high-risk IAM changes such as new root access key creation or policy modifications.

```bash
# Enable AWS Config rule for IAM password policy
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "iam-password-policy",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "IAM_PASSWORD_POLICY"
    },
    "InputParameters": "{\"RequireUppercaseCharacters\":\"true\",\"RequireLowercaseCharacters\":\"true\",\"RequireSymbols\":\"true\",\"RequireNumbers\":\"true\",\"MinimumPasswordLength\":\"14\",\"MaxPasswordAge\":\"90\"}"
  }'

# EventBridge rule to detect root account usage
aws events put-rule \
  --name DetectRootUsage \
  --event-pattern '{
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "userIdentity": {"type": ["Root"]}
    }
  }'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Least Privilege | Granting only the minimum permissions required for an identity to perform its function |
| Permission Boundary | An advanced IAM feature that sets the maximum permissions an entity can have, regardless of attached policies |
| IAM Access Analyzer | AWS service that uses automated reasoning to identify resources shared externally and generate least-privilege policies from CloudTrail activity |
| Service Control Policy (SCP) | Organization-level policy that sets permission guardrails across all accounts in an AWS Organization |
| Assume Role | STS operation that returns temporary security credentials for cross-account or service-to-service access |
| Credential Report | AWS-generated CSV listing all IAM users, their access keys, MFA status, and last activity timestamps |
| Policy Condition | Constraints in IAM policies that restrict when and how permissions apply, such as MFA requirements or IP ranges |
| Identity Federation | Allowing external identity providers to grant temporary AWS access without creating IAM users |

## Tools & Systems

- **AWS IAM Access Analyzer**: Generates least-privilege policies from CloudTrail activity and identifies resources shared with external entities
- **AWS Config**: Continuously evaluates IAM configuration compliance against managed and custom rules
- **AWS Security Hub**: Aggregates IAM security findings from Access Analyzer, Config, and third-party tools into a unified dashboard
- **IAM Policy Simulator**: Tests the effects of IAM policies before deployment by simulating API calls against policy evaluation logic
- **Prowler**: Open-source AWS security assessment tool that runs over 300 checks including IAM best practices and CIS benchmark controls

## Common Scenarios

### Scenario: Developer Role Over-Provisioned with AdministratorAccess

**Context**: A startup attached the AWS-managed AdministratorAccess policy to all developer roles for speed during early development. A security audit reveals 15 roles with full account access while developers only use S3, Lambda, and DynamoDB.

**Approach**:
1. Enable IAM Access Analyzer and generate policy recommendations based on 90 days of CloudTrail data for each role
2. Create scoped policies allowing only the specific S3 buckets, Lambda functions, and DynamoDB tables each team accesses
3. Attach a permission boundary denying IAM, Organizations, and billing actions
4. Deploy the new policies in a parallel role with CloudTrail monitoring before replacing the original
5. Remove AdministratorAccess and rotate all access keys

**Pitfalls**: Replacing policies without a parallel testing period causes service disruptions. Forgetting to scope Lambda:InvokeFunction to specific function ARNs leaves lateral movement paths open.

### Scenario: Rotating Compromised Access Keys Across Multiple Services

**Context**: An access key is found in a public GitHub repository. The key belongs to an IAM user with S3 and EC2 permissions across three AWS accounts.

**Approach**:
1. Immediately deactivate the compromised key using `aws iam update-access-key --status Inactive`
2. Review CloudTrail logs for all API calls made with the compromised key in the past 30 days
3. Create a new access key for the user and update all dependent services and CI/CD pipelines
4. Delete the compromised key after confirming all services use the new credentials
5. Migrate the workload to use IAM roles with STS temporary credentials to prevent future key exposure

**Pitfalls**: Deleting the key before deactivating it prevents forensic analysis of which services relied on it. Failing to check all three accounts for unauthorized activity leaves potential backdoors undetected.

## Output Format

```
IAM Security Assessment Report
==============================
Account ID: 123456789012
Assessment Date: 2025-02-23
Analyzer: IAM Access Analyzer + Prowler v4.3

CRITICAL FINDINGS:
[C-001] Root account has active access keys
  - Resource: arn:aws:iam::123456789012:root
  - Remediation: Delete root access keys, enable MFA on root
  - CIS Benchmark: 1.4 (Ensure no root account access key exists)

[C-002] IAM user 'deploy-bot' has AdministratorAccess with no MFA
  - Resource: arn:aws:iam::123456789012:user/deploy-bot
  - Last Activity: 2025-02-20
  - Remediation: Replace with IAM role, enforce MFA condition

HIGH FINDINGS:
[H-001] 3 IAM policies use wildcard Resource "*" with sensitive actions
  - Policies: DevPolicy, CIPolicy, LegacyAdminPolicy
  - Remediation: Scope resources to specific ARNs using Access Analyzer

[H-002] 7 access keys older than 90 days detected
  - Users: svc-backup, svc-monitoring, dev-alice, dev-bob, ...
  - Remediation: Rotate keys, migrate to role-based access

SUMMARY:
  Total Findings: 14
  Critical: 2 | High: 4 | Medium: 5 | Low: 3
  Compliance Score: 62% (CIS AWS Foundations Benchmark v3.0)
```
