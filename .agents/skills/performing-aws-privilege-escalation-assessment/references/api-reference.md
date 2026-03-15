# API Reference: Performing AWS Privilege Escalation Assessment

## AWS IAM API (boto3)

| Method | Description |
|--------|-------------|
| `iam.list_users()` | Enumerate all IAM users |
| `iam.list_attached_user_policies(UserName)` | List managed policies attached to user |
| `iam.list_user_policies(UserName)` | List inline policies on a user |
| `iam.get_policy_version(PolicyArn, VersionId)` | Get policy document for analysis |
| `iam.list_roles()` | Enumerate all IAM roles |
| `iam.list_attached_role_policies(RoleName)` | List managed policies on a role |
| `iam.list_groups_for_user(UserName)` | List group memberships for a user |
| `iam.simulate_principal_policy(PolicySourceArn, ActionNames)` | Test permissions |

## AWS STS API

| Method | Description |
|--------|-------------|
| `sts.get_caller_identity()` | Identify current principal (user/role/account) |
| `sts.assume_role(RoleArn, RoleSessionName)` | Assume a role for privilege escalation test |

## Pacu Modules (CLI)

| Module | Description |
|--------|-------------|
| `iam__enum_users_roles_policies_groups` | Full IAM enumeration |
| `iam__privesc_scan` | Scan for 21+ privilege escalation vectors |
| `iam__backdoor_users_keys` | Test access key creation ability |
| `lambda__backdoor_new_roles` | Test Lambda-based escalation |

## Key Libraries

- **boto3** (`pip install boto3`): AWS SDK for IAM, STS, and service enumeration
- **pacu** (`pip install pacu`): AWS exploitation framework (CLI-based)
- **pmapper** (Principal Mapper): Graph-based IAM privilege analysis
- **cloudfox**: Cloud penetration testing tool for AWS enumeration

## Dangerous IAM Actions

| Action | Escalation Vector |
|--------|-------------------|
| `iam:CreatePolicyVersion` | Create new policy version with admin permissions |
| `iam:AttachUserPolicy` | Attach AdministratorAccess to self |
| `iam:PassRole` + `lambda:CreateFunction` | Create Lambda with privileged role |
| `iam:PutUserPolicy` | Add inline admin policy to self |
| `sts:AssumeRole` | Assume more-privileged role |
| `iam:UpdateAssumeRolePolicy` | Modify role trust to allow self-assumption |

## Configuration

| Variable | Description |
|----------|-------------|
| `AWS_PROFILE` | AWS CLI profile with test credentials |
| `AWS_DEFAULT_REGION` | Default AWS region for API calls |

## References

- [Rhino Security: AWS IAM Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Pacu GitHub](https://github.com/RhinoSecurityLabs/pacu)
- [AWS IAM API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/)
- [Principal Mapper](https://github.com/nccgroup/PMapper)
