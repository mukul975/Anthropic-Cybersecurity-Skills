# API Reference: Performing Cloud Penetration Testing with Pacu

## Pacu CLI Commands

| Command | Description |
|---------|-------------|
| `pacu --new-session <name>` | Create a new Pacu session |
| `pacu --session <name> --module-name <module>` | Run a specific module |
| `pacu --session <name> --list-modules` | List all available modules |
| `pacu --session <name> --module-name <module> --module-args "<args>"` | Run module with arguments |

## Pacu IAM Modules

| Module | Description |
|--------|-------------|
| `iam__enum_users_roles_policies_groups` | Full IAM enumeration |
| `iam__privesc_scan` | Scan for 21+ privilege escalation vectors |
| `iam__backdoor_users_keys` | Test ability to create access keys |
| `iam__backdoor_assume_role` | Test role assumption capabilities |

## Pacu Enumeration Modules

| Module | Description |
|--------|-------------|
| `ec2__enum` | Enumerate EC2 instances, security groups, and VPCs |
| `s3__enum` | Enumerate S3 buckets and check permissions |
| `lambda__enum` | Enumerate Lambda functions and configurations |
| `secretsmanager__enum` | Enumerate Secrets Manager secrets |

## boto3 Fallback Methods

| Method | Description |
|--------|-------------|
| `sts.get_caller_identity()` | Identify current credentials |
| `iam.list_users()` | Enumerate IAM users |
| `iam.get_policy_version()` | Analyze policy documents |

## Key Libraries

- **pacu** (`pip install pacu`): AWS exploitation framework by Rhino Security Labs
- **boto3** (`pip install boto3`): AWS SDK for direct API enumeration fallback
- **subprocess** (stdlib): Execute Pacu modules as subprocesses

## Configuration

| Variable | Description |
|----------|-------------|
| `AWS_PROFILE` | AWS CLI profile with test credentials |
| `AWS_ACCESS_KEY_ID` | Access key for Pacu session |
| `AWS_SECRET_ACCESS_KEY` | Secret key for Pacu session |
| `AWS_DEFAULT_REGION` | Default AWS region |

## Pacu Session Data

| File | Description |
|------|-------------|
| `~/.pacu/sessions/<name>/` | Session directory with enumerated data |
| `~/.pacu/sessions/<name>/downloads/` | Downloaded files from modules |

## References

- [Pacu GitHub](https://github.com/RhinoSecurityLabs/pacu)
- [Pacu Wiki](https://github.com/RhinoSecurityLabs/pacu/wiki)
- [Rhino Security: AWS Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [AWS Penetration Testing Policy](https://aws.amazon.com/security/penetration-testing/)
