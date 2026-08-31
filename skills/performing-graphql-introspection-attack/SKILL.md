---
name: performing-graphql-introspection-attack
description: Performs GraphQL introspection attacks that extract the full API schema (types, queries, mutations, subscriptions, field definitions), map the attack surface, test query depth/complexity limits, and exploit GraphQL-specific weaknesses such as batching attacks, alias-based brute force, and nested query DoS. Use when performing GraphQL security testing, schema enumeration, or GraphQL API penetration testing. Do not use for focused depth-limit and nested-query DoS testing - use performing-graphql-depth-limit-attack.
domain: cybersecurity
subdomain: api-security
tags:
- api-security
- graphql
- introspection
- schema-extraction
- query-abuse
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
mitre_attack:
- T1190
- T1059.007
- T1552.001
- T1110
---
# Performing GraphQL Introspection Attack

## When to Use

- Testing GraphQL endpoints for exposed introspection that reveals the complete API schema
- Mapping the attack surface of a GraphQL API to identify sensitive queries, mutations, and types
- Testing for GraphQL-specific vulnerabilities including query depth abuse, batching attacks, and field-level authorization
- Assessing GraphQL implementations where introspection is disabled but schema can be reconstructed through error messages
- Evaluating defenses against resource exhaustion through deeply nested or complex GraphQL queries

**Do not use** without written authorization. Schema extraction and query abuse testing can impact service availability.

## Prerequisites

- Written authorization specifying the GraphQL endpoint and testing scope
- Burp Suite Professional with InQL extension (v6.1+) for automated schema analysis
- Python 3.10+ with `requests` and `gql` libraries
- GraphQL Voyager or GraphQL Playground for schema visualization
- Clairvoyance tool for schema reconstruction when introspection is disabled
- Wordlists for GraphQL field and type name brute-forcing


> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Workflow

### Step 1: GraphQL Endpoint Discovery

```python
import requests
import json

TARGET = "https://target-api.example.com"
headers = {"Content-Type": "application/json"}

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/gql", "/query",
    "/api/graphql", "/api/gql", "/api/v1/graphql",
    "/v1/graphql", "/v2/graphql",
    "/graphql/console", "/graphql/playground",
    "/graphiql", "/altair", "/explorer",
    "/graph", "/api/graph",
]

# Probe for GraphQL endpoints
for path in GRAPHQL_PATHS:
    # Test with a simple introspection query
    query = {"query": "{ __typename }"}
    try:
        resp = requests.post(f"{TARGET}{path}", headers=headers, json=query, timeout=5)
        if resp.status_code == 200 and ("data" in resp.text or "__typename" in resp.text):
            print(f"[FOUND] GraphQL endpoint: {TARGET}{path}")
            print(f"  Response: {resp.text[:200]}")
    except requests.exceptions.RequestException:
        pass

    # Also test GET method
    try:
        resp = requests.get(f"{TARGET}{path}?query={{__typename}}", timeout=5)
        if resp.status_code == 200 and ("data" in resp.text or "__typename" in resp.text):
            print(f"[FOUND] GraphQL endpoint (GET): {TARGET}{path}")
    except requests.exceptions.RequestException:
        pass
```

### Step 2: Full Introspection Query

Send the standard `IntrospectionQuery` (querying `__schema` for query/mutation/subscription types, all types with their fields and args, and directives) to the discovered endpoint. If the server returns the schema, introspection is enabled: categorize custom vs built-in (`__`-prefixed) types, summarize the query/mutation/subscription roots, and save the raw schema to `graphql_schema.json` for later analysis. A restricted or errored response indicates introspection is disabled (proceed to Step 4).

See `references/attack-scripts.md` (Step 2) for the full `FULL_INTROSPECTION` query and schema-parsing script.

### Step 3: Sensitive Data Identification in Schema

```python
# Analyze the extracted schema for sensitive fields and types
SENSITIVE_INDICATORS = {
    "field_names": [
        "password", "passwordHash", "secret", "token", "apiKey", "ssn",
        "socialSecurity", "creditCard", "cardNumber", "cvv", "pin",
        "privateKey", "internalId", "salary", "bankAccount", "taxId",
        "mfaSecret", "refreshToken", "sessionId", "debugInfo"
    ],
    "type_names": [
        "Admin", "Internal", "Debug", "Secret", "Private",
        "SystemConfig", "AuditLog", "PaymentInfo", "Credential"
    ],
    "mutation_names": [
        "deleteUser", "resetPassword", "changeRole", "elevatePrivilege",
        "createAdmin", "disableMFA", "exportData", "deleteAuditLog",
        "updateConfig", "runMigration", "executeQuery"
    ]
}

if "data" in schema:
    print("\n=== Sensitive Schema Analysis ===\n")

    for t in custom_types:
        # Check type names
        for sensitive_type in SENSITIVE_INDICATORS["type_names"]:
            if sensitive_type.lower() in t["name"].lower():
                print(f"[SENSITIVE TYPE] {t['name']}")

        # Check field names
        if t.get("fields"):
            for field in t["fields"]:
                for sensitive_field in SENSITIVE_INDICATORS["field_names"]:
                    if sensitive_field.lower() in field["name"].lower():
                        print(f"[SENSITIVE FIELD] {t['name']}.{field['name']}")

    # Check mutation names
    if mutations:
        mutation_type = next((t for t in types if t["name"] == mutations["name"]), None)
        if mutation_type and mutation_type.get("fields"):
            for mutation in mutation_type["fields"]:
                for sensitive_mut in SENSITIVE_INDICATORS["mutation_names"]:
                    if sensitive_mut.lower() in mutation["name"].lower():
                        print(f"[SENSITIVE MUTATION] {mutation['name']}")
```

### Step 4: Schema Reconstruction When Introspection is Disabled

When introspection is blocked, reconstruct the schema from error messages. GraphQL's "Did you mean" field suggestions leak valid field names: brute-force a field wordlist against common type names (`user`, `me`, `admin`, `order`, etc.) and harvest both directly-valid fields and the suggestions in error responses. (The Clairvoyance tool automates this same technique.)

See `references/attack-scripts.md` (Step 4) for the `bruteforce_field()` function and the `FIELD_WORDLIST`.

### Step 5: GraphQL Attack Techniques

With the schema (or reconstructed fields) in hand, test GraphQL-specific weaknesses:

- **Alias-based batching** — pack many `login` attempts into one request via aliases to bypass per-request rate limiting.
- **Query depth attack** — deeply nested queries (e.g. `users { friends { friends ... } }`) to test for missing depth limits (DoS).
- **Field duplication / wide query** — repeat an expensive field hundreds of times via aliases for resource exhaustion.
- **Batched queries** — send an array of hundreds of queries in a single HTTP request.
- **Circular fragment** — self-referencing fragments to trigger infinite expansion (DoS).

See `references/attack-scripts.md` (Step 5) for the five attack functions.

### Step 6: Field-Level Authorization Testing

```python
# Test if different user roles can access the same fields
user_token = "Bearer <regular_user_token>"
admin_token_val = "Bearer <admin_token>"

# Query sensitive fields as regular user
sensitive_queries = [
    {
        "name": "User PII fields",
        "query": '{ users { id email ssn dateOfBirth salary internalNotes } }'
    },
    {
        "name": "Admin mutations",
        "query": 'mutation { deleteUser(id: "1002") { success } }'
    },
    {
        "name": "System config",
        "query": '{ systemConfig { databaseUrl secretKey apiKeys } }'
    },
    {
        "name": "Audit logs",
        "query": '{ auditLogs { action userId ipAddress timestamp } }'
    },
]

for sq in sensitive_queries:
    # Test as regular user
    resp_user = requests.post(GRAPHQL_URL,
        headers={**headers, "Authorization": user_token},
        json={"query": sq["query"]})

    # Test as admin
    resp_admin = requests.post(GRAPHQL_URL,
        headers={**headers, "Authorization": admin_token_val},
        json={"query": sq["query"]})

    user_ok = resp_user.status_code == 200 and "errors" not in resp_user.json()
    admin_ok = resp_admin.status_code == 200 and "errors" not in resp_admin.json()

    if user_ok and admin_ok:
        print(f"[BFLA] {sq['name']}: Both user and admin can access")
    elif user_ok and not admin_ok:
        print(f"[ANOMALY] {sq['name']}: User can access but admin cannot")
    elif not user_ok and admin_ok:
        print(f"[SECURE] {sq['name']}: Only admin can access")
    else:
        print(f"[BLOCKED] {sq['name']}: Neither can access")
```

## Key Concepts

| Term | Definition |
|------|------------|
| **GraphQL Introspection** | Built-in capability to query the schema definition, exposing all types, fields, queries, mutations, and subscriptions available in the API |
| **Query Depth Attack** | Sending deeply nested queries that cause exponential resolver execution, consuming server resources and potentially causing DoS |
| **Alias-Based Batching** | Using GraphQL aliases to execute multiple operations in a single request, bypassing per-request rate limiting |
| **Schema Reconstruction** | Reconstructing the GraphQL schema when introspection is disabled by analyzing error messages and field suggestions |
| **Field-Level Authorization** | Controlling access to individual fields within a GraphQL type based on the authenticated user's role or permissions |
| **Query Complexity Analysis** | Calculating the computational cost of a GraphQL query before execution to enforce resource limits |

## Tools & Systems

- **InQL (Burp Suite Extension)**: Automated GraphQL introspection, schema analysis, and attack generation with support for schema brute-forcing
- **Clairvoyance**: Schema reconstruction tool that works even when introspection is disabled, using error-based field discovery
- **GraphQL Voyager**: Visual schema explorer that generates interactive diagrams from introspection results
- **Altair GraphQL Client**: Feature-rich GraphQL IDE for crafting and testing queries with authentication support
- **graphql-cop**: GraphQL security auditor that tests for common misconfigurations including introspection, field suggestions, and query limits

## Common Scenarios

### Scenario: E-Commerce GraphQL API Security Assessment

**Context**: An e-commerce platform migrated from REST to GraphQL. The GraphQL endpoint serves the web and mobile frontends. Introspection was left enabled during development and was not disabled for production.

**Approach**:
1. Run full introspection query against `/graphql` endpoint - complete schema extracted with 45 types, 120 queries, and 38 mutations
2. Identify sensitive types: `AdminUser`, `PaymentInfo`, `InternalConfig`, `AuditLog`
3. Discover that `User` type exposes `passwordHash`, `mfaSecret`, and `lastLoginIp` fields
4. Find admin mutations accessible to regular users: `deleteUser`, `updateRole`, `exportAllOrders`
5. Test query depth: no limit enforced, nested query 50 levels deep executes successfully and takes 45 seconds
6. Test alias batching: 1000 login attempts in a single request bypass rate limiting
7. Test batch queries: array of 500 queries accepted without limit
8. Schema reveals internal `InternalConfig` type with `databaseConnectionString` and `stripeSecretKey` fields

**Pitfalls**:
- Assuming introspection is the only way to discover the schema (error messages and field suggestions reveal information even when introspection is disabled)
- Not testing mutations which often have weaker authorization than queries
- Missing subscription endpoints that may expose real-time data streams without authentication
- Not testing query complexity limits with realistic payloads that trigger expensive database operations
- Ignoring that GraphQL over WebSocket (subscriptions) may have different authentication requirements

## Output Format

```
## Finding: GraphQL Introspection Enabled with Sensitive Schema Exposure

**ID**: API-GQL-001
**Severity**: High (CVSS 7.5)
**Affected Endpoint**: POST /graphql
**Tools Used**: InQL, Clairvoyance, custom Python scripts

**Description**:
The GraphQL endpoint has introspection enabled in production, exposing
the complete API schema including 45 types, 120 queries, and 38 mutations.
The schema reveals sensitive internal types (AdminUser, PaymentInfo,
InternalConfig) and exposes fields containing password hashes, MFA secrets,
and database connection strings. No query depth or complexity limits are
enforced, enabling denial-of-service through nested queries.

**Schema Highlights**:
- User.passwordHash: bcrypt hash exposed
- User.mfaSecret: TOTP secret exposed (allows MFA bypass)
- InternalConfig.databaseConnectionString: Production DB credentials
- InternalConfig.stripeSecretKey: Payment processing API key
- 12 admin mutations accessible to regular users

**Impact**:
An attacker can extract the complete API schema, identify sensitive
fields, access password hashes and MFA secrets for any user, retrieve
production database credentials, and execute admin-only mutations.

**Remediation**:
1. Disable introspection in production: set introspection to false in the GraphQL server config
2. Implement field-level authorization using GraphQL directives (@auth, @hasRole)
3. Remove sensitive fields from the schema or restrict them with authorization middleware
4. Implement query depth limiting (max 10 levels) and complexity scoring
5. Disable field suggestions in error messages to prevent schema reconstruction
6. Rate limit GraphQL requests per query, not just per HTTP request
```
