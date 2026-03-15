# API Reference: Threat intelligence lifecycle audit

## API Details
PyMISP: get_event(), add_event(), search(), stix2: Indicator, Malware, Bundle

## Installation
```bash
pip install pymisp stix2
```

## Libraries

| Library | Use |
|---------|-----|
| `pymisp` | pymisp client/SDK |
| `stix2` | stix2 client/SDK |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
