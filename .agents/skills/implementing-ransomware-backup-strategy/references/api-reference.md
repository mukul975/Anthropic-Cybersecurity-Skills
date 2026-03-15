# API Reference: Ransomware backup strategy audit

## API Endpoints
S3: list_buckets, get_bucket_versioning; AWS Backup: list_backup_plans; 3-2-1 rule

## Installation
```bash
pip install boto3 subprocess
```

## Libraries

| Library | Use |
|---------|-----|
| `boto3` | boto3 SDK/client |
| `subprocess` | subprocess SDK/client |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
