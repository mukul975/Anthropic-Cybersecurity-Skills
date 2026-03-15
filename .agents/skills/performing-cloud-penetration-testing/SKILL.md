---
name: performing-cloud-penetration-testing
description: >
  Performs authorized penetration testing of cloud environments across AWS, Azure, and GCP to
  identify IAM misconfigurations, exposed storage buckets, overly permissive security groups,
  serverless function vulnerabilities, and cloud-specific attack paths from initial access to
  account compromise. The tester uses cloud-native tools and specialized frameworks like Pacu
  and ScoutSuite to enumerate and exploit cloud infrastructure. Activates for requests involving
  cloud pentest, AWS security assessment, Azure penetration testing, or cloud infrastructure
  security testing.
domain: cybersecurity
subdomain: penetration-testing
tags: [cloud-pentest, AWS-security, Azure-security, IAM-exploitation, cloud-infrastructure]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Performing Cloud Penetration Testing

## When to Use

- Assessing the security posture of cloud infrastructure before or after migration from on-premises
- Testing IAM policies, security groups, and network ACLs for overly permissive configurations
- Evaluating the security of serverless architectures (Lambda, Azure Functions, Cloud Functions)
- Identifying exposed cloud storage (S3 buckets, Azure Blob containers, GCS buckets) containing sensitive data
- Testing the effectiveness of cloud security controls (GuardDuty, Defender for Cloud, Security Command Center)

**Do not use** without both written authorization from the cloud account owner AND compliance with the cloud provider's penetration testing policy (AWS requires no prior approval for most services; Azure and GCP require notification or approval for certain test types).

## Prerequisites

- Written authorization specifying target cloud accounts, regions, and services in scope
- Compliance with cloud provider penetration testing policies (AWS Penetration Testing Policy, Azure Penetration Testing Rules, GCP Acceptable Use Policy)
- Cloud credentials at various privilege levels (read-only, developer, admin) for testing authorization boundaries
- Pacu (AWS), PowerZure (Azure), or GCP-specific exploitation frameworks installed
- ScoutSuite or Prowler for automated cloud security posture assessment
- AWS CLI, Azure CLI, and/or gcloud CLI configured with test credentials

## Workflow

### Step 1: Cloud Reconnaissance and Enumeration

Enumerate the cloud environment to map the attack surface:

**AWS Enumeration:**
- `aws sts get-caller-identity` - Verify current identity and account
- `aws iam list-users` - List all IAM users
- `aws iam list-roles` - List all IAM roles and their trust policies
- `aws s3 ls` - List all S3 buckets
- `aws ec2 describe-instances --region us-east-1` - List EC2 instances
- `aws lambda list-functions` - List Lambda functions
- `aws rds describe-db-instances` - List RDS databases
- Use Pacu for automated enumeration: `run iam__enum_permissions`, `run iam__enum_users_roles_policies_groups`

**Azure Enumeration:**
- `az account list` - List subscriptions
- `az ad user list` - List Azure AD users
- `az vm list` - List virtual machines
- `az storage account list` - List storage accounts
- `az keyvault list` - List key vaults
- `az webapp list` - List web applications

**Cross-Cloud:**
- Run ScoutSuite for comprehensive posture assessment: `scout aws --profile <profile>` or `scout azure --cli`
- Run Prowler for AWS CIS benchmark compliance: `prowler aws`

### Step 2: IAM and Identity Exploitation

Test IAM policies for privilege escalation paths:

**AWS IAM Escalation:**
- Check for overpermissive policies: `aws iam get-user-policy`, `aws iam list-attached-user-policies`
- Test known IAM escalation paths:
  - `iam:CreatePolicyVersion` - Create a new policy version granting admin access
  - `iam:SetDefaultPolicyVersion` - Set an older, more permissive policy version as default
  - `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` - Create a Lambda with a high-privilege role
  - `iam:AttachUserPolicy` - Attach AdministratorAccess to the current user
  - `sts:AssumeRole` - Assume a higher-privilege role if trust policy allows
- Use Pacu for automated escalation: `run iam__privesc_scan`

**Azure Identity Escalation:**
- Enumerate role assignments: `az role assignment list --assignee <user>`
- Check for Contributor/Owner roles at subscription level
- Test Azure AD privilege escalation through application registrations, service principals, and managed identities
- Check for Global Administrator assignments in Azure AD

### Step 3: Storage and Data Exposure

Test cloud storage services for data exposure:

- **S3 bucket security**: Test each bucket for:
  - Public access: `aws s3 ls s3://<bucket> --no-sign-request`
  - ACL misconfigurations: `aws s3api get-bucket-acl --bucket <bucket>`
  - Bucket policy: `aws s3api get-bucket-policy --bucket <bucket>`
  - Versioning (access deleted data): `aws s3api list-object-versions --bucket <bucket>`
- **Azure Blob exposure**: Test for public container access and shared access signature (SAS) token leakage
- **Secrets in storage**: Search storage contents for credentials, API keys, database connection strings, and PII
- **Database exposure**: Check for RDS/Azure SQL instances with public endpoints, default credentials, or security groups allowing 0.0.0.0/0 access

### Step 4: Compute and Serverless Exploitation

Test compute resources for vulnerabilities:

- **EC2 instance metadata**: From a compromised instance, query `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to extract IAM role credentials
- **IMDSv1 exploitation**: Test if IMDSv2 is enforced. IMDSv1 is vulnerable to SSRF-based credential theft.
- **Lambda function analysis**: Download Lambda function code (`aws lambda get-function --function-name <name>`) and review for hardcoded credentials, insecure dependencies, and injection vulnerabilities
- **Container security**: Test ECS/EKS for pod-level privilege escalation, container breakout, and service account token abuse
- **User data scripts**: `aws ec2 describe-instance-attribute --instance-id <id> --attribute userData` to find credentials in startup scripts

### Step 5: Network and Security Group Assessment

Test network controls for misconfigurations:

- **Security group analysis**: Identify groups allowing 0.0.0.0/0 ingress on sensitive ports (SSH/22, RDP/3389, database ports)
- **VPC flow logs**: Check if VPC flow logs are enabled for forensic capability
- **Cross-account access**: Test for overly permissive resource policies that allow access from other AWS accounts
- **VPC peering**: Identify VPC peering connections and test if peered VPCs have access to sensitive resources
- **VPN and Direct Connect**: Identify hybrid connectivity and test if cloud-to-on-premises access controls are enforced

## Key Concepts

| Term | Definition |
|------|------------|
| **IAM Privilege Escalation** | Exploiting overly permissive IAM policies to elevate from limited access to administrative control over the cloud account |
| **Instance Metadata Service (IMDS)** | An HTTP endpoint (169.254.169.254) on cloud instances that provides instance configuration and IAM role credentials, exploitable via SSRF |
| **Assumed Role** | An IAM role that a user or service temporarily assumes to gain its permissions, governed by trust policies that define who can assume the role |
| **SCPs (Service Control Policies)** | Organization-level policies in AWS Organizations that set permission boundaries for accounts, overriding IAM policies |
| **Managed Identity** | Azure's equivalent of AWS IAM roles for services, providing automatic credential management for Azure resources |
| **Resource Policy** | Access control policy attached to a cloud resource (S3 bucket, Lambda function, SQS queue) that defines cross-account and public access |

## Tools & Systems

- **Pacu**: Open-source AWS exploitation framework supporting IAM enumeration, privilege escalation, data exfiltration, and persistence
- **ScoutSuite**: Multi-cloud security auditing tool that assesses security posture across AWS, Azure, GCP, and Oracle Cloud against security best practices
- **Prowler**: AWS and Azure security assessment tool covering CIS benchmarks, PCI-DSS, HIPAA, and GDPR compliance checks
- **CloudFox**: Tool for identifying exploitable attack paths in cloud infrastructure by analyzing IAM roles, permissions, and trust relationships
- **Steampipe**: SQL-based query engine for cloud infrastructure that enables complex queries across cloud provider APIs

## Common Scenarios

### Scenario: AWS Cloud Penetration Test for a SaaS Company

**Context**: A SaaS company hosts its entire platform on AWS across 3 accounts (production, staging, development). The tester is given read-only IAM credentials in the development account. The goal is to determine if the development account can be used to pivot to production.

**Approach**:
1. Enumerate the development account with Pacu: discover 45 Lambda functions, 12 EC2 instances, 8 S3 buckets, and 23 IAM roles
2. Find that the developer role can invoke Lambda functions; one Lambda function has a role with S3 full access and STS assume-role permissions
3. Modify the Lambda function code to assume a cross-account role in the production account (trust policy allows the Lambda role)
4. From the assumed production role, enumerate S3 buckets and discover customer data in an unencrypted bucket
5. Find that the production EC2 instances use IMDSv1, which combined with an SSRF vulnerability in the web application could allow credential theft
6. Document the complete attack path from development read-only to production data access

**Pitfalls**:
- Not checking the cloud provider's penetration testing policy and accidentally triggering automated abuse detection
- Focusing only on IaaS (EC2, VMs) while ignoring serverless functions, managed services, and storage that contain the most sensitive data
- Missing cross-account trust relationships that provide lateral movement between cloud accounts
- Not testing IMDSv2 enforcement, which is the most common cloud-specific vulnerability

## Output Format

```
## Finding: Cross-Account Role Trust Allows Development-to-Production Pivot

**ID**: CLOUD-002
**Severity**: Critical (CVSS 9.6)
**Cloud Provider**: AWS
**Affected Account**: Production (111222333444)
**Exploited From**: Development (555666777888)

**Description**:
The production account IAM role "ProdDataAccess" has a trust policy that allows
the Lambda execution role "LambdaDevRole" in the development account to assume
it. This cross-account trust, combined with the developer's ability to modify
Lambda function code, creates a path from development read-only access to
production data access.

**Attack Chain**:
1. Enumerate Lambda functions in dev: aws lambda list-functions
2. Identify LambdaDevRole has sts:AssumeRole permission
3. Modify Lambda to assume ProdDataAccess: aws sts assume-role --role-arn arn:aws:iam::111222333444:role/ProdDataAccess
4. From assumed role: aws s3 ls s3://prod-customer-data -> 2.3 million customer records

**Impact**:
An attacker compromising any developer credential can access production
customer data (2.3 million records) without directly attacking the production
account.

**Remediation**:
1. Restrict the ProdDataAccess trust policy to specific production roles only
2. Remove sts:AssumeRole from the LambdaDevRole policy
3. Implement AWS Organizations SCPs to prevent cross-account role assumption from development
4. Enable CloudTrail alerts for cross-account AssumeRole events
5. Encrypt S3 bucket with KMS key that the development account cannot access
```
