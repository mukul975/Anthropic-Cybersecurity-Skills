# API Reference: Cloud incident containment agent

## API Details
EC2: stop_instances, modify_instance_attribute; IAM: update_access_key; SG: revoke_ingress

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
