# API Reference: Cartography cloud asset inventory agent

## API Details
neo4j driver, cartography --neo4j-uri, AWS resource mapping, relationship graphing

## Installation
```bash
pip install boto3 subprocess
```

## Libraries

| Library | Use |
|---------|-----|
| `boto3` | boto3 |
| `subprocess` | subprocess |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "target": "URL", "findings": [], "risk_level": "HIGH"}
```
