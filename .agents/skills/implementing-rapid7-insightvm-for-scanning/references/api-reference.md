# API Reference: Rapid7 InsightVM scanning configuration audit

## API Endpoints
InsightVM API: GET /api/3/sites, GET /api/3/scans, GET /api/3/vulnerabilities, scan engines

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
