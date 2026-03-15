# API Reference: Velociraptor IR collection audit

## API Details
Velociraptor API: POST /api/v1/CreateFlow, GET /api/v1/GetFlowResults, VQL queries

## Installation
```bash
pip install requests subprocess
```

## Libraries

| Library | Use |
|---------|-----|
| `requests` | requests client/SDK |
| `subprocess` | subprocess client/SDK |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
