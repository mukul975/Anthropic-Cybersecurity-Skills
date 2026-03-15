# API Reference — Performing GraphQL Introspection Attack

## Libraries Used
- **requests**: Send GraphQL introspection queries and depth test payloads

## CLI Interface
```
python agent.py introspect --url <graphql_endpoint> [--auth-header "Bearer token"]
python agent.py depth --url <graphql_endpoint> [--max-depth 10]
```

## Core Functions

### `run_introspection(url, headers)` — Execute `__schema` introspection query
Returns: types, queries, mutations, sensitive field detection.

### `test_depth_limit(url, max_depth, headers)` — Test query depth enforcement
Sends increasingly nested queries to detect missing depth limits.

## Sensitive Field Patterns
`password`, `token`, `secret`, `credential`, `ssn`, `credit_card`, `api_key`

## Dependencies
```
pip install requests
```
