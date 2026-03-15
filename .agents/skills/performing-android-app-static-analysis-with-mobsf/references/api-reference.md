# API Reference: MobSF Android static analysis agent

## API Details
MobSF API: POST /api/v1/upload, POST /api/v1/scan, GET /api/v1/report_json, API key auth

## Installation
```bash
pip install requests
```

## Libraries

| Library | Use |
|---------|-----|
| `requests` | requests |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "target": "URL", "findings": [], "risk_level": "HIGH"}
```
