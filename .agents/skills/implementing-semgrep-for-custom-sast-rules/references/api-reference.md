# API Reference: Semgrep custom SAST rule audit

## API Details
semgrep --config=auto --json --output=report.json, custom rules YAML, pattern-based

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
