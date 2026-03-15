# API Reference: PCI DSS compliance control audit

## API Endpoints
Requirements: network segmentation, encryption, access control, logging, vulnerability mgmt

## Installation
```bash
pip install requests jinja2
```

## Libraries

| Library | Use |
|---------|-----|
| `requests` | requests SDK/client |
| `jinja2` | jinja2 SDK/client |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
