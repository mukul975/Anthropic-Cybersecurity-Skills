# API Reference: OPA policy-as-code implementation audit

## API Endpoints
OPA: POST /v1/data/{package}, PUT /v1/policies/{id}, GET /v1/data, Rego policy language

## Installation
```bash
pip install requests
```

## Libraries

| Library | Use |
|---------|-----|
| `requests` | requests SDK/client |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
