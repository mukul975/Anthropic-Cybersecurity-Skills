# API Reference: Purdue model OT network segmentation audit

## API Endpoints
Levels L0-L5, DMZ at L3.5, firewall rules, asset classification, traffic flow validation

## Installation
```bash
pip install scapy requests
```

## Libraries

| Library | Use |
|---------|-----|
| `scapy` | scapy SDK/client |
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
