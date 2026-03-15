# API Reference: Implementing AWS Security Hub Compliance

## Libraries

### boto3 -- Security Hub + S3 Remediation
- **Install**: `pip install boto3`
- **Docs**: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html

### Key Security Hub Methods

| Method | Description |
|--------|-------------|
| `enable_security_hub()` | Enable Security Hub with standards |
| `batch_enable_standards()` | Enable CIS, FSBP, PCI DSS, NIST |
| `get_findings()` | Query findings with compliance filters |
| `batch_update_findings()` | Update workflow status and add notes |
| `create_insight()` | Custom compliance aggregation views |
| `create_finding_aggregator()` | Cross-region consolidation |
| `enable_organization_admin_account()` | Org-wide admin delegation |
| `update_organization_configuration()` | Auto-enable for new accounts |

### Key S3 Remediation Methods

| Method | Description |
|--------|-------------|
| `put_public_access_block()` | Block all public access on bucket |
| `get_bucket_encryption()` | Check encryption configuration |
| `put_bucket_encryption()` | Enable default SSE-S3 or SSE-KMS |

## Finding Filters

| Filter Field | Values |
|-------------|--------|
| `ComplianceStatus` | PASSED, FAILED, WARNING, NOT_AVAILABLE |
| `SeverityLabel` | CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL |
| `WorkflowStatus` | NEW, NOTIFIED, RESOLVED, SUPPRESSED |
| `RecordState` | ACTIVE, ARCHIVED |
| `GeneratorId` | Standard-specific prefix for filtering |

## Compliance Standards

| Standard | Generator ID Prefix |
|----------|-------------------|
| AWS FSBP | `aws-foundational-security-best-practices` |
| CIS AWS | `cis-aws-foundations-benchmark` |
| PCI DSS | `pci-dss` |
| NIST 800-53 | `nist-800-53` |

## EventBridge Auto-Remediation Pattern
- Source: `aws.securityhub`
- Detail type: `Security Hub Findings - Imported`
- Target: Lambda function for automated fix
- Best practice: Only auto-remediate safe controls (S3 public access, encryption)

## External References
- Security Hub Compliance: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html
- ASFF Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
- Auto-Remediation Patterns: https://aws.amazon.com/blogs/security/automated-response-and-remediation-with-aws-security-hub/
