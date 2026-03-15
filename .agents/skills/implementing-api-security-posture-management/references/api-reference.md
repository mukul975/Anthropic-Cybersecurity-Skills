# API Reference: Implementing API Security Posture Management

## API Discovery from Traffic

```python
import re
# Normalize paths: /users/123 -> /users/{id}
normalized = re.sub(r"/\d+", "/{id}", path)
normalized = re.sub(r"/[0-9a-f-]{8,}", "/{id}", normalized)
```

## API Sensitivity Classification

| Category | Patterns | Sensitivity |
|----------|----------|-------------|
| PII | `/users`, `/profile`, `/account` | HIGH |
| Financial | `/payments`, `/billing` | HIGH |
| Auth | `/login`, `/token`, `/oauth` | HIGH |
| Admin | `/admin`, `/config` | HIGH |
| Health | `/health`, `/status` | LOW |

## Risk Scoring Model

| Factor | Points | Description |
|--------|--------|-------------|
| High sensitivity data | +30 | PII, financial, auth |
| High error rate (>10%) | +20 | Possible abuse |
| State-changing methods | +10 | PUT, DELETE, PATCH |
| High consumer count | +10 | Large attack surface |
| Auth endpoint | +15 | Credential target |

## 42Crunch API Audit

```bash
# CI/CD integration
curl -X POST https://platform.42crunch.com/api/v1/apis \
  -H "X-API-KEY: $API_KEY" \
  -F "file=@openapi.yaml"
```

## Salt Security API

```python
import requests
headers = {"Authorization": "Bearer <token>"}
# Discover shadow APIs
resp = requests.get("https://api.salt.security/v1/apis", headers=headers)
```

### References

- OWASP API Security Top 10: https://owasp.org/API-Security/
- 42Crunch: https://42crunch.com/
- Salt Security: https://salt.security/
