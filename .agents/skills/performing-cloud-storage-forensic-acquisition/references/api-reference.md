# API Reference: Cloud storage forensic acquisition agent

## API Details
S3: list_objects_v2, get_object, get_bucket_versioning; GCS: list_blobs, download_blob

## Installation
```bash
pip install boto3
```

## Libraries

| Library | Use |
|---------|-----|
| `boto3` | boto3 |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "target": "URL", "findings": [], "risk_level": "HIGH"}
```
