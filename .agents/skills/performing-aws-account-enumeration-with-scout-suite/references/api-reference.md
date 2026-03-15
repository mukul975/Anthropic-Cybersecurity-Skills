# API Reference: AWS Scout Suite security audit agent

## API Details
scout --provider aws --report-dir output, boto3.client('iam'), finding analysis

## Installation
```bash
pip install boto3 subprocess
```

## Libraries

| Library | Use |
|---------|-----|
| `boto3` | boto3 |
| `subprocess` | subprocess |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "target": "URL", "findings": [], "risk_level": "HIGH"}
```
