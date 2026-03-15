# API Reference: LaZagne credential access detection agent

## API Details
LaZagne all -oJ, browser credential detection, WiFi password extraction, log analysis

## Installation
```bash
pip install subprocess pathlib
```

## Libraries

| Library | Use |
|---------|-----|
| `subprocess` | subprocess |
| `pathlib` | pathlib |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "target": "URL", "findings": [], "risk_level": "HIGH"}
```
