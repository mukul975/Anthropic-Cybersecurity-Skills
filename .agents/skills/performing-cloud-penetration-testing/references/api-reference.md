# API Reference: Performing Cloud Penetration Testing

## AWS S3 API (boto3)

| Method | Description |
|--------|-------------|
| `s3.list_buckets()` | Enumerate all S3 buckets in account |
| `s3.get_bucket_acl(Bucket)` | Check bucket ACL for public grants |
| `s3.get_bucket_policy(Bucket)` | Get bucket policy for public access |
| `s3.get_bucket_encryption(Bucket)` | Check default encryption status |

## AWS EC2 API

| Method | Description |
|--------|-------------|
| `ec2.describe_security_groups()` | Enumerate security groups and ingress rules |
| `ec2.describe_instances()` | List instances with metadata options (IMDSv1/v2) |
| `ec2.describe_network_interfaces()` | Enumerate ENIs and public IPs |

## AWS Lambda API

| Method | Description |
|--------|-------------|
| `lambda.list_functions()` | Enumerate Lambda functions |
| `lambda.get_function(FunctionName)` | Get function config including env vars |
| `lambda.get_policy(FunctionName)` | Get resource-based policy |

## AWS IAM API

| Method | Description |
|--------|-------------|
| `iam.list_users()` | Enumerate IAM users |
| `iam.list_roles()` | Enumerate IAM roles and trust policies |
| `iam.get_policy_version()` | Analyze policy documents |

## Key Libraries

- **boto3** (`pip install boto3`): AWS SDK for all service enumeration
- **ScoutSuite** (`pip install scoutsuite`): Multi-cloud security auditing tool
- **prowler**: AWS/Azure/GCP security best practices assessment
- **cloudfox**: Cloud penetration testing enumeration

## Configuration

| Variable | Description |
|----------|-------------|
| `AWS_PROFILE` | AWS CLI profile with test credentials |
| `AWS_DEFAULT_REGION` | Target AWS region |

## References

- [AWS Penetration Testing Policy](https://aws.amazon.com/security/penetration-testing/)
- [ScoutSuite GitHub](https://github.com/nccgroup/ScoutSuite)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [CloudFox](https://github.com/BishopFox/cloudfox)
- [HackTricks Cloud](https://cloud.hacktricks.xyz/)
