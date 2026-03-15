# API Reference: STIX/TAXII feed integration audit

## API Details
taxii2client.Server(), Collection.get_objects(), stix2.parse(), indicator extraction

## Installation
```bash
pip install stix2 taxii2client
```

## Libraries

| Library | Use |
|---------|-----|
| `stix2` | stix2 client/SDK |
| `taxii2client` | taxii2client client/SDK |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
