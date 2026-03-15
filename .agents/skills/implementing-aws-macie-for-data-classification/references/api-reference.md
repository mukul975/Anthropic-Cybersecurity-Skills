# API Reference: AWS Macie Data Classification Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| boto3 | >=1.28 | AWS SDK for Macie2 sensitive data discovery |

## CLI Usage

```bash
python scripts/agent.py \
  --profile security-audit \
  --region us-east-1 \
  --output-dir /reports/ \
  --output macie_report.json
```

## Functions

### `get_macie_client(profile, region)`
Creates boto3 Macie2 client with optional named profile.

### `enable_macie(client) -> dict`
Calls `client.get_macie_session()` to check status, then `client.enable_macie()` if needed.

### `list_s3_buckets_summary(client) -> list`
Calls `client.describe_buckets()` to get bucket inventory with encryption, public access, and classifiable object counts.

### `create_classification_job(client, bucket_names, job_name) -> dict`
Calls `client.create_classification_job(jobType="ONE_TIME", s3JobDefinition={...})` for targeted sensitive data discovery.

### `get_finding_statistics(client) -> dict`
Calls `client.get_finding_statistics(groupBy=...)` for severity and type breakdowns.

### `list_findings(client, severity, max_results) -> list`
Calls `client.list_findings()` with severity criterion, then `client.get_findings(findingIds=[...])` for details.

### `generate_report(client) -> dict`
Orchestrates all functions and compiles summary with public bucket identification.

## boto3 Macie2 Methods Used

| Method | Purpose |
|--------|---------|
| `enable_macie(status)` | Enable Macie service |
| `describe_buckets(criteria)` | S3 bucket inventory |
| `create_classification_job(...)` | Start discovery job |
| `get_finding_statistics(groupBy)` | Finding aggregations |
| `list_findings(findingCriteria)` | Filter findings |
| `get_findings(findingIds)` | Detailed finding data |

## Output Schema

```json
{
  "summary": {"total_buckets": 45, "public_buckets": 2, "high_findings": 12},
  "bucket_inventory": [{"name": "my-bucket", "public_access": "NOT_PUBLIC"}],
  "high_findings": [{"type": "SensitiveData:S3Object/Personal", "bucket": "data-lake"}]
}
```
