# API Reference: HashiCorp Vault secrets management audit

## API Details
hvac.Client(url, token): read_secret(), write_secret(), sys.list_auth_methods(), seal_status

## Installation
```bash
pip install hvac
```

## Libraries

| Library | Use |
|---------|-----|
| `hvac` | hvac client/SDK |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
