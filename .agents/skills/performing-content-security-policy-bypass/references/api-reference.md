# API Reference: CSP bypass testing agent

## API Details
Content-Security-Policy header parsing, directive analysis, bypass vectors, nonce detection

## Installation
```bash
pip install requests re
```

## Libraries

| Library | Use |
|---------|-----|
| `requests` | requests |
| `re` | re |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "target": "URL", "findings": [], "risk_level": "HIGH"}
```
