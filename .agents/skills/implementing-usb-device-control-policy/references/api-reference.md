# API Reference: USB device control policy audit

## API Details
PowerShell: Get-PnpDevice, udevadm info, registry HKLM USB control, device whitelist

## Installation
```bash
pip install subprocess
```

## Libraries

| Library | Use |
|---------|-----|
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
