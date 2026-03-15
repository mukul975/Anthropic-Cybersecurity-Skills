---
name: performing-service-account-audit
description: Audit service accounts across enterprise infrastructure to identify orphaned, over-privileged, and non-compliant accounts. This skill covers discovery of service accounts in Active Directory, cloud pl
domain: cybersecurity
subdomain: identity-access-management
tags: [iam, identity, access-control, service-accounts, audit, governance]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Service Account Audit

## Overview
Audit service accounts across enterprise infrastructure to identify orphaned, over-privileged, and non-compliant accounts. This skill covers discovery of service accounts in Active Directory, cloud platforms, databases, and applications, assessing privilege levels, identifying missing owners, and enforcing lifecycle policies.

## Objectives
- Discover all service accounts across AD, cloud, databases, and applications
- Identify orphaned accounts with no valid owner or associated application
- Assess privilege levels and flag over-privileged service accounts
- Check for non-rotating passwords and weak authentication
- Map service account dependencies for safe remediation
- Generate compliance reports for SOX, PCI DSS, and HIPAA audits

## Key Concepts

### Service Account Types
1. **AD Service Accounts**: Windows services, scheduled tasks, IIS app pools
2. **Managed Service Accounts (gMSA)**: AD-managed automatic password rotation
3. **Cloud IAM Service Accounts**: AWS IAM roles/users, Azure service principals, GCP service accounts
4. **Database Service Accounts**: Application connection accounts, replication accounts
5. **Application Service Accounts**: API keys, bot accounts, integration accounts

### Audit Dimensions
- **Ownership**: Who is responsible for this account?
- **Purpose**: What application/service uses this account?
- **Privileges**: What permissions does this account have?
- **Authentication**: How does this account authenticate (password, key, certificate)?
- **Rotation**: When was the credential last changed?
- **Activity**: When was this account last used?

## Implementation Steps

### Step 1: Discovery - Active Directory
1. Query AD for all service accounts (filter by description, OU, naming convention)
2. Identify accounts with `ServicePrincipalName` set
3. List accounts in privileged groups (Domain Admins, Enterprise Admins)
4. Check for gMSA vs traditional service accounts
5. Identify accounts with `PasswordNeverExpires` flag

### Step 2: Discovery - Cloud Platforms
- **AWS**: List IAM users with access keys, check last used date, identify unused roles
- **Azure**: Enumerate service principals, app registrations, managed identities
- **GCP**: List service accounts, check key age, identify unused permissions

### Step 3: Assessment
- Flag accounts with admin/privileged group membership
- Check password age against rotation policy (90 days max)
- Identify accounts with no login activity in 90+ days
- Verify account ownership against CMDB/asset inventory
- Check for shared credentials (same password hash across accounts)

### Step 4: Risk Classification
- **Critical**: Domain/cloud admin privileges, no password rotation
- **High**: Access to sensitive data, no identified owner
- **Medium**: Standard service permissions, password older than 90 days
- **Low**: Read-only access, managed credentials (gMSA, managed identity)

### Step 5: Remediation
- Disable orphaned accounts after validation with application teams
- Convert traditional service accounts to gMSA where possible
- Rotate credentials older than policy threshold
- Reduce privileges to minimum required
- Assign owners and document dependencies

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Account Management | AC-2 | Service account lifecycle |
| Account Review | AC-2(3) | Periodic review of accounts |
| Least Privilege | AC-6 | Minimum service account permissions |
| Authenticator Management | IA-5 | Service credential rotation |
| Audit Review | AU-6 | Review service account activity |

## Common Pitfalls
- Disabling service accounts without verifying application dependencies first
- Not discovering service accounts outside of Active Directory
- Missing cloud service principals and managed identities
- Not checking for interactive logon rights on service accounts
- Failing to document dependencies before remediation

## Verification
- [ ] Service accounts inventoried across all platforms
- [ ] Each account has assigned owner
- [ ] Privileged service accounts documented with justification
- [ ] Password rotation compliance checked
- [ ] Orphaned accounts flagged for remediation
- [ ] gMSA migration candidates identified
- [ ] Compliance report generated
