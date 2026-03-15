# API Reference: Cloud Security Posture Management Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| boto3 | >=1.28 | AWS SDK for Security Hub findings and compliance |
| prowler | >=4.0 | Open-source cloud security scanner (optional, via subprocess) |

## CLI Usage

```bash
python scripts/agent.py \
  --profile security-audit \
  --region us-east-1 \
  --output-dir /reports/ \
  --output cspm_report.json
```

## Functions

### `get_securityhub_client(profile, region)`
Creates boto3 Security Hub client.

### `get_findings_summary(client, max_results) -> dict`
Calls `client.get_findings()` filtered to NEW/ACTIVE findings, groups by severity.

### `get_compliance_summary(client) -> list`
Calls `client.get_enabled_standards()` then `describe_standards_controls()` per standard. Returns compliance percentages.

### `run_prowler_scan(profile, region) -> dict`
Executes `prowler aws --output-formats json` via subprocess with 10-minute timeout.

### `generate_report(client, profile, region) -> dict`
Combines Security Hub and Prowler results into unified CSPM report.

## boto3 Security Hub Methods

| Method | Purpose |
|--------|---------|
| `get_findings(Filters, MaxResults)` | Retrieve active findings |
| `get_enabled_standards()` | List enabled compliance standards |
| `describe_standards_controls(StandardsSubscriptionArn)` | Control-level compliance |

## Output Schema

```json
{
  "summary": {"finding_counts": {"CRITICAL": 3, "HIGH": 12}, "total_findings": 45},
  "compliance_standards": [{"standard": "cis-aws-foundations-benchmark", "compliance_pct": 78.5}],
  "recommendations": ["Remediate 3 CRITICAL findings immediately"]
}
```
