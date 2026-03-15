# API Reference: GraphQL Security Assessment

## GraphQL Introspection Query

```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name type { name kind } } }
  }
}
```

## Security Test Endpoints

| Test | Query | Expected Secure Response |
|------|-------|-------------------------|
| Introspection | `{ __schema { types { name } } }` | Error: introspection disabled |
| Depth limit | Nested `{ users { friends { ... } } }` | Error: max depth exceeded |
| Batch queries | `[{query: "..."}, {query: "..."}]` | Error or single-query only |
| Aliases | `{ a1: __typename a2: __typename ... }` | Error: alias limit exceeded |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP client for GraphQL POST requests |
| `gql` | >=3.4 | Python GraphQL client with transport support |

## graphql-cop CLI

```bash
pip install graphql-cop
graphql-cop -t https://target.example.com/graphql
```

## clairvoyance (Schema Enumeration)

```bash
python3 -m clairvoyance -u <url> -w <wordlist> -o schema.json
```

## References

- GraphQL specification: https://spec.graphql.org/
- InQL Burp extension: https://github.com/doyensec/inql
- clairvoyance: https://github.com/nikitastupin/clairvoyance
- graphql-cop: https://github.com/dolevf/graphql-cop
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
