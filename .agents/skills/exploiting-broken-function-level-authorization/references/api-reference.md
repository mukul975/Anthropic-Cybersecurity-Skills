# API Reference: Broken Function Level Authorization (BFLA)

## OWASP API5:2023 — Broken Function Level Authorization

### Description
API endpoints expose functions that should be restricted to specific roles.
Low-privileged users can invoke admin-level functionality.

### Common Patterns
| Pattern | Example |
|---------|---------|
| Guessable admin paths | `/api/admin/users` |
| Method switching | POST allowed but PUT bypasses auth |
| Role parameter manipulation | `{"role": "admin"}` in request |
| Vertical privilege escalation | User accessing admin endpoints |

## Testing Methodology

### Step 1: Discover Endpoints
```bash
# From OpenAPI spec
curl https://api.target.com/swagger.json | jq '.paths | keys'

# From JavaScript source
grep -oP '["'"'"']/api/[^"'"'"']+' app.js
```

### Step 2: Test with Low-Priv Token
```bash
curl -H "Authorization: Bearer <low_priv_token>" \
     https://api.target.com/api/admin/users
```

### Step 3: Test HTTP Method Switching
```bash
# If GET returns 403, try POST/PUT/DELETE
curl -X PUT -H "Authorization: Bearer <low_priv_token>" \
     https://api.target.com/api/admin/users/1
```

## Python requests Library

### Request with Token
```python
headers = {"Authorization": f"Bearer {token}"}
resp = requests.get(url, headers=headers, timeout=10, verify=False)
```

### Method Switching
```python
for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
    resp = requests.request(method, url, headers=headers, timeout=10)
    if resp.status_code < 400:
        print(f"Accessible via {method}: {resp.status_code}")
```

## Common Admin Endpoints to Test

```
/admin
/api/admin
/api/v1/admin/users
/api/internal
/manage
/api/config
/api/debug
/api/users/all
/api/system/settings
/graphql (with admin mutations)
```

## Burp Suite — Authorization Testing

### Autorize Extension
1. Install Autorize from BApp Store
2. Set low-privilege cookie/token
3. Browse application as admin
4. Autorize replays requests with low-priv token
5. Compare responses for authorization bypass

## Response Analysis

| Indicator | Meaning |
|-----------|---------|
| 200 with data | Full access (vulnerability) |
| 200 empty body | Possible partial bypass |
| 403 Forbidden | Properly restricted |
| 401 Unauthorized | Auth required |
| 405 Method Not Allowed | Method restricted |
