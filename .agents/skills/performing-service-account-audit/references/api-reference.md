# API Reference: Service Account Audit

## Active Directory PowerShell Cmdlets

| Cmdlet | Description |
|--------|-------------|
| `Get-ADUser -Filter {ServicePrincipalName -ne '$null'}` | Find accounts with SPNs |
| `Get-ADServiceAccount -Filter *` | List managed service accounts |
| `Get-ADGroupMember -Identity "Domain Admins"` | List privileged group members |
| `Search-ADAccount -PasswordNeverExpires` | Find non-expiring passwords |
| `Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00` | Find inactive accounts |

## AWS IAM CLI Commands

| Command | Description |
|---------|-------------|
| `aws iam list-users` | List all IAM users |
| `aws iam list-access-keys --user-name <name>` | List access keys for user |
| `aws iam get-access-key-last-used --access-key-id <id>` | Check key last used date |
| `aws iam list-user-policies --user-name <name>` | List inline policies |
| `aws iam list-attached-user-policies --user-name <name>` | List managed policies |
| `aws iam generate-credential-report` | Generate credential report |

## Azure CLI Commands

| Command | Description |
|---------|-------------|
| `az ad sp list --all` | List all service principals |
| `az ad app list --all` | List all app registrations |
| `az ad app credential list --id <app-id>` | List credential expiration |

## Risk Classification

| Level | Score Range | Criteria |
|-------|------------|----------|
| Critical | >= 40 | Domain admin + stale password + no owner |
| High | 25-39 | Privileged group membership or orphaned |
| Medium | 10-24 | Password age exceeded or PasswordNeverExpires |
| Low | 0-9 | Standard permissions, managed credentials |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute PowerShell and AWS CLI commands |
| `json` | stdlib | Parse CLI output |
| `ldap3` | >=2.9 | Direct LDAP queries to Active Directory |
| `boto3` | >=1.26 | AWS IAM programmatic access |

## References

- NIST SP 800-53 AC-2: Account Management
- CIS Benchmark for Active Directory
- AWS IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- Microsoft gMSA: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
