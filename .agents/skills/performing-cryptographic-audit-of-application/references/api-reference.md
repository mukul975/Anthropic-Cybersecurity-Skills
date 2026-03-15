# API Reference: Application cryptographic audit agent

## API Details
TLS version check, cipher suite audit, certificate validation, key strength analysis

## Installation
```bash
pip install cryptography ssl
```

## Libraries

| Library | Use |
|---------|-----|
| `cryptography` | cryptography |
| `ssl` | ssl |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "target": "URL", "findings": [], "risk_level": "HIGH"}
```
