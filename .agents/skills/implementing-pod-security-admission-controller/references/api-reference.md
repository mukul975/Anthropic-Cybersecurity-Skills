# API Reference: Kubernetes Pod Security Admission audit

## API Endpoints
CoreV1Api: list_namespace(), labels: pod-security.kubernetes.io/enforce, baseline/restricted

## Installation
```bash
pip install kubernetes
```

## Libraries

| Library | Use |
|---------|-----|
| `kubernetes` | kubernetes SDK/client |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
