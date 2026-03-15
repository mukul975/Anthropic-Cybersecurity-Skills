# Cloud Infrastructure Penetration Test — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| boto3 | `pip install boto3` | AWS SDK for Python — EC2, S3, IAM, security group enumeration |
| ScoutSuite | `pip install scoutsuite` | Multi-cloud security auditing tool |
| pacu | `pip install pacu` | AWS exploitation framework for penetration testing |

## Key boto3 Methods

| Method | Description |
|--------|-------------|
| `ec2.describe_security_groups()` | List all security groups with inbound/outbound rules |
| `ec2.describe_instances()` | Enumerate EC2 instances with metadata options |
| `s3.list_buckets()` | List all S3 buckets in the account |
| `s3.get_bucket_acl(Bucket=name)` | Check bucket ACL for public access grants |
| `s3.get_bucket_policy(Bucket=name)` | Retrieve bucket resource policy JSON |
| `iam.list_users()` | Enumerate all IAM users |
| `iam.list_attached_user_policies(UserName=u)` | List managed policies attached to a user |
| `iam.list_access_keys(UserName=u)` | List access keys with creation dates |
| `iam.simulate_principal_policy()` | Test effective permissions for a principal |
| `sts.get_caller_identity()` | Identify current credentials (account, ARN) |

## ScoutSuite CLI

```bash
scout aws --no-browser --report-dir ./report
scout azure --cli --no-browser
scout gcp --no-browser
```

## Key Constants

| Constant | Value |
|----------|-------|
| IMDSv2 required | `HttpTokens: "required"` |
| Public ACL URI | `http://acs.amazonaws.com/groups/global/AllUsers` |
| Admin policy ARN | `arn:aws:iam::aws:policy/AdministratorAccess` |

## External References

- [AWS Penetration Testing Policy](https://aws.amazon.com/security/penetration-testing/)
- [ScoutSuite Documentation](https://github.com/nccgroup/ScoutSuite/wiki)
- [Pacu Wiki](https://github.com/RhinoSecurityLabs/pacu/wiki)
- [boto3 EC2 Reference](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html)
