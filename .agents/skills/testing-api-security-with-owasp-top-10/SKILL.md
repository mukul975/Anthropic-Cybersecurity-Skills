---
name: testing-api-security-with-owasp-top-10
description: Systematically assessing REST and GraphQL API endpoints against the OWASP API Security Top 10 risks using automated and manual testing techniques.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, api-security, owasp, rest-api, graphql, burpsuite, postman]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing API Security with OWASP Top 10

## When to Use

- During authorized API penetration testing engagements
- When assessing REST, GraphQL, or gRPC APIs for security vulnerabilities
- Before deploying new API endpoints to production environments
- When reviewing API security posture against the OWASP API Security Top 10 (2023)
- For validating API gateway security controls and rate limiting effectiveness

## Prerequisites

- **Authorization**: Written scope document covering all API endpoints to be tested
- **Burp Suite Professional**: For intercepting and modifying API requests
- **Postman**: For organizing and executing API test collections
- **ffuf**: For API endpoint and parameter fuzzing
- **curl/httpie**: Command-line HTTP clients for manual testing
- **API documentation**: Swagger/OpenAPI spec, GraphQL schema, or API docs
- **jq**: JSON processor for parsing API responses (`apt install jq`)

## Workflow

### Step 1: Discover and Map API Endpoints

Enumerate all available API endpoints and understand the API surface.

```bash
# If OpenAPI/Swagger spec is available, download it
curl -s "https://api.target.example.com/swagger.json" | jq '.paths | keys[]'
curl -s "https://api.target.example.com/v2/api-docs" | jq '.paths | keys[]'
curl -s "https://api.target.example.com/openapi.yaml"

# Fuzz for API endpoints
ffuf -u "https://api.target.example.com/api/v1/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,401,403,405 \
  -fc 404 \
  -H "Content-Type: application/json" \
  -o api-enum.json -of json

# Fuzz for API versions
for v in v1 v2 v3 v4 beta internal admin; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://api.target.example.com/api/$v/users")
  echo "$v: $status"
done

# Check for GraphQL endpoint
for path in graphql graphiql playground query gql; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' \
    "https://api.target.example.com/$path")
  echo "$path: $status"
done
```

### Step 2: Test API1 - Broken Object Level Authorization (BOLA)

Test whether users can access objects belonging to other users by manipulating IDs.

```bash
# Authenticate as User A and get their resources
TOKEN_A="Bearer eyJhbGciOiJIUzI1NiIs..."
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/101/orders" | jq .

# Try accessing User B's resources with User A's token
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/102/orders" | jq .

# Fuzz object IDs with Burp Intruder or ffuf
ffuf -u "https://api.target.example.com/api/v1/orders/FUZZ" \
  -w <(seq 1 1000) \
  -H "Authorization: $TOKEN_A" \
  -mc 200 -t 10 -rate 50

# Test IDOR with different ID formats
# Numeric: /users/102
# UUID: /users/550e8400-e29b-41d4-a716-446655440000
# Encoded: /users/MTAy (base64)
```

### Step 3: Test API2 - Broken Authentication

Assess authentication mechanisms for weaknesses.

```bash
# Test for missing authentication
curl -s "https://api.target.example.com/api/v1/users" | jq .

# Test JWT token vulnerabilities
# Decode JWT without verification
echo "eyJhbGciOiJIUzI1NiIs..." | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Test "alg: none" attack
# Header: {"alg":"none","typ":"JWT"}
# Create unsigned token with modified claims

# Test brute-force protection on login
ffuf -u "https://api.target.example.com/api/v1/auth/login" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"FUZZ"}' \
  -w /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt \
  -mc 200 -t 5 -rate 10

# Test password reset flow
curl -s -X POST "https://api.target.example.com/api/v1/auth/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'

# Check if token is in response body instead of email only
```

### Step 4: Test API3 - Broken Object Property Level Authorization

Test for excessive data exposure and mass assignment vulnerabilities.

```bash
# Check for excessive data in responses
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/101" | jq .
# Look for: password hashes, SSNs, internal IDs, admin flags, PII

# Test mass assignment - try adding admin properties
curl -s -X PUT \
  -H "Authorization: $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","role":"admin","is_admin":true}' \
  "https://api.target.example.com/api/v1/users/101" | jq .

# Test with PATCH method
curl -s -X PATCH \
  -H "Authorization: $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","balance":999999}' \
  "https://api.target.example.com/api/v1/users/101" | jq .

# Check if filtering parameters expose more data
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/101?fields=all" | jq .
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/101?include=password,ssn" | jq .
```

### Step 5: Test API4/API6 - Rate Limiting and Unrestricted Access to Sensitive Flows

Verify rate limiting and resource consumption controls.

```bash
# Test rate limiting on authentication endpoint
for i in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}' \
    "https://api.target.example.com/api/v1/auth/login")
  echo "Attempt $i: $status"
  if [ "$status" == "429" ]; then
    echo "Rate limited at attempt $i"
    break
  fi
done

# Test for unrestricted resource consumption
# Large pagination
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users?limit=100000&offset=0" | jq '. | length'

# GraphQL depth/complexity attack
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: $TOKEN_A" \
  -d '{"query":"{ users { friends { friends { friends { friends { name } } } } } }"}' \
  "https://api.target.example.com/graphql"

# Test SMS/email flooding via OTP endpoint
for i in $(seq 1 20); do
  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"phone":"+1234567890"}' \
    "https://api.target.example.com/api/v1/auth/send-otp"
done
```

### Step 6: Test API5 - Broken Function Level Authorization

Check for privilege escalation through administrative endpoints.

```bash
# Test admin endpoints with regular user token
ADMIN_ENDPOINTS=(
  "/api/v1/admin/users"
  "/api/v1/admin/settings"
  "/api/v1/admin/logs"
  "/api/v1/internal/config"
  "/api/v1/users?role=admin"
  "/api/v1/admin/export"
)

for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
  for method in GET POST PUT DELETE; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      -X "$method" \
      -H "Authorization: $TOKEN_A" \
      -H "Content-Type: application/json" \
      "https://api.target.example.com$endpoint")
    if [ "$status" != "403" ] && [ "$status" != "401" ] && [ "$status" != "404" ]; then
      echo "POTENTIAL ISSUE: $method $endpoint returned $status"
    fi
  done
done

# Test HTTP method switching
# If GET /admin/users returns 403, try:
curl -s -X POST -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/admin/users"
```

### Step 7: Test API7-API10 - SSRF, Misconfiguration, Inventory, and Unsafe Consumption

```bash
# API7: Server-Side Request Forgery
curl -s -X POST -H "Authorization: $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}' \
  "https://api.target.example.com/api/v1/fetch-url"

curl -s -X POST -H "Authorization: $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url":"http://127.0.0.1:6379/"}' \
  "https://api.target.example.com/api/v1/webhooks"

# API8: Security Misconfiguration
# Check CORS policy
curl -s -I -H "Origin: https://evil.example.com" \
  "https://api.target.example.com/api/v1/users" | grep -i "access-control"

# Check for verbose error messages
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"invalid": "data' \
  "https://api.target.example.com/api/v1/users"

# Check security headers
curl -s -I "https://api.target.example.com/api/v1/health" | grep -iE \
  "(x-frame|x-content|strict-transport|content-security|x-xss)"

# API9: Improper Inventory Management
# Test deprecated API versions
for v in v0 v1 v2 v3; do
  curl -s -o /dev/null -w "$v: %{http_code}\n" \
    "https://api.target.example.com/api/$v/users"
done

# API10: Unsafe Consumption of APIs
# Test if the API blindly trusts third-party data
# Check webhook/callback implementations for injection
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **BOLA (API1)** | Broken Object Level Authorization - accessing objects belonging to other users |
| **Broken Authentication (API2)** | Weak authentication mechanisms allowing credential stuffing or token manipulation |
| **BOPLA (API3)** | Broken Object Property Level Authorization - excessive data exposure or mass assignment |
| **Unrestricted Resource Consumption (API4)** | Missing rate limiting enabling DoS or brute-force attacks |
| **Broken Function Level Auth (API5)** | Regular users accessing admin-level API functions |
| **SSRF (API7)** | Server-Side Request Forgery through API parameters accepting URLs |
| **Security Misconfiguration (API8)** | Missing security headers, verbose errors, permissive CORS |
| **Improper Inventory (API9)** | Undocumented, deprecated, or shadow API endpoints left exposed |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | API interception, scanning, and manual testing |
| **Postman** | API collection management and automated test execution |
| **ffuf** | API endpoint and parameter fuzzing |
| **Kiterunner** | API endpoint discovery using common API path patterns |
| **jwt_tool** | JWT token analysis, manipulation, and attack automation |
| **GraphQL Voyager** | GraphQL schema visualization and introspection analysis |
| **Arjun** | HTTP parameter discovery for API endpoints |

## Common Scenarios

### Scenario 1: BOLA in E-commerce API
User A can access User B's order details by changing the order ID in `/api/v1/orders/{id}`. The API only checks authentication but not authorization on the object level.

### Scenario 2: Mass Assignment on User Profile
The user update endpoint accepts a `role` field in the JSON body. By adding `"role":"admin"` to a profile update request, a regular user escalates to administrator privileges.

### Scenario 3: Deprecated API Version Bypass
The `/api/v2/users` endpoint has proper rate limiting, but `/api/v1/users` (still active) has no rate limiting. Attackers use the old version to brute-force credentials.

### Scenario 4: GraphQL Introspection Data Leak
GraphQL introspection is enabled in production, exposing the entire schema including internal queries, mutations, and sensitive field names that are not used in the frontend.

## Output Format

```
## API Security Assessment Report

**Target**: api.target.example.com
**API Type**: REST (OpenAPI 3.0)
**Assessment Date**: 2024-01-15
**OWASP API Security Top 10 (2023) Coverage**

| Risk | Status | Severity | Details |
|------|--------|----------|---------|
| API1: BOLA | VULNERABLE | Critical | /api/v1/orders/{id} - IDOR confirmed |
| API2: Broken Auth | VULNERABLE | High | No rate limit on /auth/login |
| API3: BOPLA | VULNERABLE | High | User role modifiable via mass assignment |
| API4: Resource Consumption | VULNERABLE | Medium | No pagination limit enforced |
| API5: Function Level Auth | PASS | - | Admin endpoints properly restricted |
| API6: Unrestricted Sensitive Flows | VULNERABLE | Medium | OTP endpoint lacks rate limiting |
| API7: SSRF | PASS | - | URL parameters properly validated |
| API8: Misconfiguration | VULNERABLE | Medium | Verbose stack traces in error responses |
| API9: Improper Inventory | VULNERABLE | Low | API v1 still accessible without docs |
| API10: Unsafe Consumption | NOT TESTED | - | No third-party API integrations found |

### Critical Finding: BOLA on Orders API
Authenticated users can access any order by iterating order IDs.
Tested range: 1-1000, 847 valid orders accessible.
PII exposure: names, addresses, payment details.
```
