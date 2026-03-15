# Duo MFA Configuration — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| duo_client | `pip install duo_client` | Official Duo SDK for Python |
| requests | `pip install requests` | HTTP client for Admin API |

## Duo Admin API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/v1/users` | List all users with enrollment status |
| GET | `/admin/v1/users/{user_id}` | Get user details and devices |
| GET | `/admin/v1/info/summary` | Account summary (user count, integrations) |
| GET | `/admin/v2/logs/authentication` | Authentication logs (v2 with paging) |
| POST | `/admin/v1/users/enroll` | Enroll new user for MFA |
| POST | `/admin/v1/users/{id}/bypass_codes` | Generate bypass codes |

## Authentication (HMAC Signing)

```python
import duo_client
admin_api = duo_client.Admin(
    ikey="DIXXXXXXXXXXXXXXXXXX",
    skey="YourSecretKey",
    host="api-XXXXXXXX.duosecurity.com"
)
users = admin_api.get_users()
```

## User Status Values

| Status | Description |
|--------|-------------|
| active | User enrolled and can authenticate |
| bypass | MFA bypassed — security risk |
| disabled | User account disabled |
| locked_out | Temporarily locked due to failed attempts |

## External References

- [Duo Admin API Reference](https://duo.com/docs/adminapi)
- [duo_client Python SDK](https://github.com/duosecurity/duo_client_python)
- [Duo Auth API](https://duo.com/docs/authapi)
