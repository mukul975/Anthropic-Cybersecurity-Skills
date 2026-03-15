# Cloudflare Access Zero Trust — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | Cloudflare API v4 client |

## Cloudflare Access API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/{id}/access/apps` | List Access applications |
| GET | `/accounts/{id}/access/apps/{id}/policies` | List app policies |
| GET | `/accounts/{id}/access/groups` | List Access groups |
| GET | `/accounts/{id}/access/identity_providers` | List IdP configs |
| GET | `/accounts/{id}/access/service_tokens` | List service tokens |
| POST | `/accounts/{id}/access/apps` | Create application |
| PUT | `/accounts/{id}/access/apps/{id}` | Update application |

## Authentication

```python
headers = {
    "Authorization": "Bearer <api_token>",
    "Content-Type": "application/json"
}
```

## Access Policy Rule Types

| Rule | Description |
|------|-------------|
| `include` | Must match (OR within group) |
| `exclude` | Must not match |
| `require` | Must match (AND) |

## External References

- [Cloudflare Access API](https://developers.cloudflare.com/api/operations/access-applications-list-access-applications)
- [Cloudflare Zero Trust Docs](https://developers.cloudflare.com/cloudflare-one/)
- [cloudflare Python SDK](https://github.com/cloudflare/cloudflare-python)
