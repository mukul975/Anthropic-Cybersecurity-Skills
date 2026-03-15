# AWS IAM Permission Boundaries - Standards Reference

## AWS IAM Policy Types

| Policy Type | Scope | Purpose |
|-------------|-------|---------|
| Identity-Based | Attached to users/roles/groups | Grants permissions |
| Resource-Based | Attached to resources (S3, KMS) | Cross-account access |
| Permission Boundary | Attached to users/roles | Maximum permission limit |
| Organizations SCP | Attached to OUs/accounts | Organization-wide limit |
| Session Policy | Passed during AssumeRole | Session-level limit |

## AWS Well-Architected Framework - Security Pillar

### SEC02 - Identity Management
- SEC02-BP02: Use temporary credentials (permission boundaries enforce this)
- SEC02-BP05: Audit and rotate credentials regularly
- SEC02-BP06: Employ user groups and attributes for fine-grained access

### SEC03 - Permissions Management
- SEC03-BP01: Define access requirements (boundary defines maximum)
- SEC03-BP02: Grant least privilege access
- SEC03-BP06: Manage access based on lifecycle
- SEC03-BP07: Analyze public and cross-account access

## CIS AWS Foundations Benchmark v3.0

- 1.4: Ensure no root account access key exists
- 1.15: Ensure IAM users receive permissions only through groups
- 1.16: Ensure IAM policies that allow full admin privileges are not attached
- 1.17: Ensure a support role has been created for incident management
- 1.22: Ensure IAM policies with admin access are reviewed regularly

## NIST SP 800-53 Mapping

- AC-2: Account Management (boundary controls role creation)
- AC-3: Access Enforcement (intersection of policies)
- AC-5: Separation of Duties (boundary prevents security role access)
- AC-6: Least Privilege (boundary enforces maximum permissions)
- AC-6(1): Authorize Access to Security Functions
- AC-6(5): Privileged Accounts (boundary limits even admin roles)
