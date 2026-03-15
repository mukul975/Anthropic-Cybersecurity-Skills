# API Reference: Implementing AWS Security Hub

## Libraries

### boto3 -- AWS Security Hub
- **Install**: `pip install boto3`
- **Docs**: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html

### Key Methods

| Method | Description |
|--------|-------------|
| `enable_security_hub()` | Activate Security Hub in an account |
| `batch_enable_standards()` | Enable compliance standards (CIS, FSBP, PCI) |
| `get_enabled_standards()` | List enabled standards and their status |
| `get_findings()` | Retrieve security findings with filters |
| `batch_update_findings()` | Update finding status (resolve, suppress) |
| `batch_import_findings()` | Import custom findings in ASFF format |
| `create_insight()` | Create custom aggregation insight |
| `create_finding_aggregator()` | Enable cross-region finding aggregation |
| `enable_organization_admin_account()` | Designate delegated admin |
| `update_organization_configuration()` | Auto-enable for org members |
| `create_action_target()` | Create custom remediation action |

## Standard ARNs

| Standard | ARN Pattern |
|----------|------------|
| CIS v5.0 | `arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/5.0.0` |
| FSBP v1.0 | `arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0` |
| PCI DSS 3.2.1 | `arn:aws:securityhub:{region}::standards/pci-dss/v/3.2.1` |
| NIST 800-53 r5 | `arn:aws:securityhub:{region}::standards/nist-800-53/v/5.0.0` |

## ASFF Finding Format (Key Fields)
- `SchemaVersion`: `"2018-10-08"`
- `Id`: Unique finding identifier
- `ProductArn`: Source product ARN
- `Severity.Label`: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
- `Compliance.Status`: PASSED, FAILED, WARNING, NOT_AVAILABLE
- `Resources[]`: Affected AWS resources
- `Workflow.Status`: NEW, NOTIFIED, RESOLVED, SUPPRESSED

## EventBridge Integration
- Source: `aws.securityhub`
- Detail type: `Security Hub Findings - Imported`
- Filter by: `Severity.Label`, `Compliance.Status`, `GeneratorId`

## External References
- Security Hub User Guide: https://docs.aws.amazon.com/securityhub/latest/userguide/
- ASFF Syntax: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
- Security Hub Controls: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html
