# API Reference: CyberArk PAM configuration audit

## API Endpoints
CyberArk: POST /PasswordVault/api/auth/cyberark/logon, GET /api/Accounts, GET /api/Safes

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
