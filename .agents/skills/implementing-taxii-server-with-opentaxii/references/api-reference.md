# API Reference: OpenTAXII server configuration audit

## API Details
TAXII 2.1: GET /taxii2/, GET /api/collections, GET /api/collections/{id}/objects

## Installation
```bash
pip install taxii2client requests
```

## Libraries

| Library | Use |
|---------|-----|
| `taxii2client` | taxii2client client/SDK |
| `requests` | requests client/SDK |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
