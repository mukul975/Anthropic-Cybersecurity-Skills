# API Reference: Patch management workflow automation

## API Endpoints
Tenable: GET /scans, Qualys: GET /api/2.0/fo/scan/, WSUS PowerShell, patch compliance tracking

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
