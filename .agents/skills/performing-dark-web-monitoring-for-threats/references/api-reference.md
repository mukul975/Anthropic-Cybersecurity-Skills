# API Reference: Dark web threat monitoring agent

## API Details
Tor SOCKS proxy, paste site monitoring, credential leak detection, brand mention tracking

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
