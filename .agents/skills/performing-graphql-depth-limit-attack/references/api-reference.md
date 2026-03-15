# API Reference — Performing GraphQL Depth Limit Attack

## Libraries Used
- **requests**: Send GraphQL queries with depth/width/batch payloads
- **time**: Measure response latency for resource exhaustion detection

## CLI Interface
```
python agent.py depth --url <endpoint> [--max-depth 20] [--auth-header "Bearer token"]
python agent.py circular --url <endpoint> --type-a User --field-a posts --type-b Post --field-b author [--depth 10]
python agent.py batch --url <endpoint> [--count 50]
python agent.py width --url <endpoint> [--width 50] [--depth 5]
```

## Core Functions

### `build_nested_query(field_name, depth, leaf)` — Construct nested query payload
Generates progressively deeper GraphQL queries for depth limit probing.

### `test_depth_limit(url, max_depth, headers)` — Probe depth enforcement
Sends queries at increasing depth (1 to max_depth). Classifies severity:
HIGH (>=15 allowed), MEDIUM (>=8), LOW (<8).

### `test_circular_query(url, type_a, field_a, type_b, field_b, depth)` — Test circular references
Builds alternating A.field_a -> B.field_b chains to test circular query handling.

### `test_batch_query(url, count, headers)` — Test batch query bypass
Sends array of N queries to check if batching bypasses per-query depth limits.

### `test_resource_exhaustion(url, width, depth, headers)` — Test wide+deep queries
Combines field width (aliases) with nesting depth. Flags SLOW_RESPONSE if >5s.

## Severity Classification
- **HIGH**: No depth limit or limit >= 15 levels
- **MEDIUM**: Depth limit 8-14 or batch queries accepted
- **LOW**: Depth limit < 8 with proper enforcement

## Dependencies
```
pip install requests
```
