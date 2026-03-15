# API Inventory and Discovery — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | HTTP probing and spec fetching |

## Common API Discovery Paths

| Path | Description |
|------|-------------|
| `/api/v1`, `/api/v2` | Versioned REST API roots |
| `/swagger.json` | Swagger 2.0 specification |
| `/openapi.json` | OpenAPI 3.x specification |
| `/graphql` | GraphQL endpoint |
| `/graphiql`, `/playground` | GraphQL IDE (introspection enabled) |
| `/api-docs`, `/docs` | API documentation page |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/health`, `/metrics` | Health/monitoring endpoints |

## OpenAPI Spec Parsing

```python
import requests
spec = requests.get("https://target.com/openapi.json").json()
for path, methods in spec["paths"].items():
    for method, details in methods.items():
        print(f"{method.upper()} {path} deprecated={details.get('deprecated', False)}")
```

## JavaScript API Extraction Patterns

| Pattern | Matches |
|---------|---------|
| `fetch("/<path>")` | Fetch API calls |
| `axios.get("/<path>")` | Axios HTTP calls |
| `"/api/v1/<resource>"` | String literal API paths |
| `"/v2/<resource>"` | Versioned API references |

## API Risk Classification

| Category | Risk | Examples |
|----------|------|---------|
| Admin/Internal | HIGH | `/admin/api`, `/internal/` |
| GraphQL exposed | HIGH | `/graphql` with introspection |
| Documentation public | MEDIUM | `/swagger.json`, `/api-docs` |
| Deprecated/zombie | HIGH | Deprecated but still responding |
| Standard versioned | LOW | `/api/v2/users` |

## OWASP API9:2023 — Improper Inventory Management

| Issue | Description |
|-------|-------------|
| Shadow APIs | Undocumented endpoints deployed without review |
| Zombie APIs | Deprecated versions still accessible |
| Missing authentication | Endpoints skipping auth middleware |
| Version sprawl | Multiple API versions maintained simultaneously |

## External References

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [Swagger/OpenAPI Spec](https://swagger.io/specification/)
- [Kiterunner API Discovery](https://github.com/assetnote/kiterunner)
