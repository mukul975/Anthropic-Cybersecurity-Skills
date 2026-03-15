# API Reference: Kubernetes RBAC configuration audit

## API Endpoints
RbacAuthorizationV1Api: list_cluster_role_binding, list_namespaced_role_binding, list_cluster_role

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
