# API Reference: Testing for Broken Access Control

## requests Library

### Authentication Patterns
```python
# Bearer token authentication
headers = {"Authorization": "Bearer <token>", "Content-Type": "application/json"}

# Cookie-based authentication
cookies = {"session": "session_value"}

# Multiple methods
resp = requests.request("DELETE", url, headers=headers)
```

## Test Categories

### Vertical Privilege Escalation
Test admin endpoints with regular user credentials:
```python
for endpoint in admin_endpoints:
    resp = requests.get(url, headers=user_headers)
    # 200 = VULNERABLE, 403 = properly restricted
```

### Horizontal Privilege Escalation (IDOR)
Access other users' resources:
```python
# Replace {id} with other user's ID
resp = requests.get(f"/api/users/{other_id}/profile", headers=user_headers)
```

### HTTP Method Override
```python
override_headers = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]
```

### Mass Assignment Fields
| Field | Description |
|-------|-------------|
| `role` | User role (admin, user) |
| `is_admin` | Boolean admin flag |
| `permissions` | Permission array |
| `access_level` | Numeric access level |
| `user_type` | User type classification |

## Response Status Interpretation
| Status | Meaning |
|--------|---------|
| 200/201 | Access granted (potential vulnerability if unexpected) |
| 401 | Not authenticated |
| 403 | Authenticated but not authorized (correct behavior) |
| 404 | Resource not found (may hide from unauthorized users) |
| 405 | Method not allowed |

## OWASP References
- A01:2021 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- WSTG Access Control: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/
- IDOR Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
