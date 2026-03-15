# API Reference: Securing AWS IAM Permissions

## boto3 IAM Client

### Installation
```bash
pip install boto3
```

### Key Methods

| Method | Description |
|--------|-------------|
| `list_users()` | List all IAM users in the account |
| `list_roles()` | List all IAM roles |
| `list_access_keys()` | List access keys for a user |
| `get_access_key_last_used()` | Get last usage info for an access key |
| `list_attached_role_policies()` | List managed policies attached to a role |
| `list_role_policies()` | List inline policy names for a role |
| `get_role_policy()` | Get inline policy document for a role |
| `list_mfa_devices()` | List MFA devices for a user |
| `get_login_profile()` | Check if user has console access |
| `generate_credential_report()` | Trigger credential report generation |
| `get_credential_report()` | Download the credential report (CSV, base64) |
| `simulate_principal_policy()` | Test effective permissions for a principal |
| `update_access_key()` | Activate or deactivate an access key |
| `put_role_permissions_boundary()` | Apply a permission boundary to a role |

## boto3 Access Analyzer Client

| Method | Description |
|--------|-------------|
| `create_analyzer()` | Create an IAM Access Analyzer (type: ACCOUNT or ORGANIZATION) |
| `list_analyzers()` | List existing analyzers |
| `list_findings()` | Get active findings for external access |
| `start_policy_generation()` | Generate least-privilege policy from CloudTrail |
| `get_generated_policy()` | Retrieve a generated policy by job ID |
| `validate_policy()` | Validate a policy against IAM best practices |

### Credential Report CSV Fields
| Field | Description |
|-------|-------------|
| `user` | IAM username |
| `arn` | User ARN |
| `password_enabled` | Whether console password is set |
| `mfa_active` | Whether MFA is enabled |
| `access_key_1_active` | Whether first access key is active |
| `access_key_1_last_used_date` | Last usage timestamp |
| `access_key_1_last_rotated` | Last rotation timestamp |

## References
- boto3 IAM docs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html
- IAM Access Analyzer: https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
