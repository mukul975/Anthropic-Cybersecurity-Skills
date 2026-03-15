# API Reference: Implementing Cloud Security Posture Management

## Libraries

### Prowler (Multi-Cloud CSPM)
- **Install**: `pip install prowler`
- **Docs**: https://docs.prowler.com/
- CLI: `prowler aws --compliance cis_level1 -M json`
- Supported: AWS, Azure, GCP, Kubernetes
- Compliance frameworks: CIS, SOC2, PCI-DSS, HIPAA, NIST 800-53, GDPR

### boto3 (AWS Posture Checks)
- **Install**: `pip install boto3`
- Key services: S3, IAM, EC2, CloudTrail, Config, SecurityHub

### ScoutSuite (Multi-Cloud Auditing)
- **Install**: `pip install scoutsuite`
- **Docs**: https://github.com/nccgroup/ScoutSuite
- CLI: `scout aws --report-dir /tmp/scout-report`

## AWS Posture Check APIs

| Service | Method | Check |
|---------|--------|-------|
| S3 | `get_public_access_block()` | Public access settings |
| S3 | `get_bucket_encryption()` | Default encryption |
| IAM | `get_account_summary()` | Root MFA status |
| IAM | `list_access_keys()` | Key age/rotation |
| EC2 | `describe_security_groups()` | Open ports (0.0.0.0/0) |
| CloudTrail | `get_trail_status()` | Logging active |
| Config | `describe_config_rules()` | Compliance rules |

## Prowler Check Categories
- IAM: Access keys, MFA, password policy, root usage
- Storage: S3 public access, encryption, versioning
- Network: Security groups, VPC flow logs, NACLs
- Logging: CloudTrail, Config, VPC flow logs
- Encryption: EBS, RDS, S3, KMS key rotation

## Severity Mapping
- **CRITICAL**: Root MFA disabled, CloudTrail off, public DB
- **HIGH**: S3 public access, open SSH/RDP, unencrypted volumes
- **MEDIUM**: Key rotation >90d, missing tags, flow logs off
- **LOW**: Informational findings, best practice suggestions

## External References
- Prowler Documentation: https://docs.prowler.com/
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- AWS Security Hub: https://docs.aws.amazon.com/securityhub/
- CIS Benchmarks: https://www.cisecurity.org/benchmark/amazon_web_services
