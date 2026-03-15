# API Reference: Kubernetes RBAC hardening audit

## API Details
RbacAuthorizationV1Api: list_cluster_role, list_cluster_role_binding, wildcard verb detection

## Installation
```bash
pip install kubernetes
```

## Libraries

| Library | Use |
|---------|-----|
| `kubernetes` | kubernetes client/SDK |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
