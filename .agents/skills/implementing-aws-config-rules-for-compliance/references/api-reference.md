# API Reference: Implementing AWS Config Rules for Compliance

## Libraries

### boto3 -- AWS Config Service
- **Install**: `pip install boto3`
- **Docs**: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/config.html

### Key Methods

| Method | Description |
|--------|-------------|
| `put_configuration_recorder()` | Create/update Config recorder |
| `start_configuration_recorder()` | Start recording configurations |
| `put_delivery_channel()` | Configure S3 delivery channel |
| `put_config_rule()` | Deploy a managed or custom Config rule |
| `get_compliance_summary_by_config_rule()` | Aggregate compliance counts |
| `get_compliance_details_by_config_rule()` | Non-compliant resources per rule |
| `put_remediation_configurations()` | Set up auto-remediation actions |
| `put_configuration_aggregator()` | Multi-account compliance aggregation |
| `describe_config_rules()` | List all deployed Config rules |
| `get_aggregate_compliance_details_by_config_rule()` | Cross-account compliance |

## Managed Rule Source Identifiers

| Rule | SourceIdentifier |
|------|-----------------|
| S3 public read | `S3_BUCKET_PUBLIC_READ_PROHIBITED` |
| S3 encryption | `S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED` |
| IAM root key | `IAM_ROOT_ACCESS_KEY_CHECK` |
| MFA console | `MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS` |
| SSH restricted | `INCOMING_SSH_DISABLED` |
| VPC flow logs | `VPC_FLOW_LOGS_ENABLED` |
| RDS encrypted | `RDS_STORAGE_ENCRYPTED` |
| EBS encrypted | `ENCRYPTED_VOLUMES` |
| CloudTrail on | `CLOUD_TRAIL_ENABLED` |

## SSM Remediation Documents

| Document | Purpose |
|----------|---------|
| `AWS-DisableS3BucketPublicReadWrite` | Block public S3 access |
| `AWS-EnableEBSEncryptionByDefault` | Enable EBS encryption |
| `AWS-DisablePublicAccessForSecurityGroup` | Remove 0.0.0.0/0 rules |

## Conformance Packs
- CIS AWS Foundations Benchmark: `Operational-Best-Practices-for-CIS`
- PCI DSS: `Operational-Best-Practices-for-PCI-DSS`
- NIST 800-53: `Operational-Best-Practices-for-NIST-800-53-rev5`

## External References
- AWS Config Rules List: https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html
- Config Conformance Packs: https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html
- Config Remediation: https://docs.aws.amazon.com/config/latest/developerguide/remediation.html
