# API Reference: Proofpoint email security gateway audit

## API Endpoints
Proofpoint TAP API v2: GET /v2/siem/clicks/blocked, GET /v2/siem/messages/delivered

## Installation
```bash
pip install requests hmac
```

## Libraries

| Library | Use |
|---------|-----|
| `requests` | requests SDK/client |
| `hmac` | hmac SDK/client |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
