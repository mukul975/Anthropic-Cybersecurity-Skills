# API Reference: Gitleaks secret scanning audit

## API Details
gitleaks detect --source=. --report-format=json, custom .gitleaks.toml rules

## Installation
```bash
pip install subprocess pathlib
```

## Libraries

| Library | Use |
|---------|-----|
| `subprocess` | subprocess client/SDK |
| `pathlib` | pathlib client/SDK |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
