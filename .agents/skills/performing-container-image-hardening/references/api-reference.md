# API Reference: Container image hardening audit agent

## API Details
trivy image --format json, docker inspect, Dockerfile lint, base image analysis

## Installation
```bash
pip install subprocess
```

## Libraries

| Library | Use |
|---------|-----|
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
