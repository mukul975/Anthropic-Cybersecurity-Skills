# API Reference: in-toto supply chain security audit

## API Details
in-toto-run, in-toto-verify, layout creation, functionary keys, supply chain steps

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
