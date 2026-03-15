# API Reference: IDOR Vulnerability Testing Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for API endpoint testing |

## CLI Usage

```bash
python scripts/agent.py \
  --url https://target.example.com \
  --token-a "eyJ..." --token-b "eyJ..." \
  --endpoints "/api/v1/users/{id}/profile" "/api/v1/orders/{id}" \
  --own-id 101 --other-id 102 \
  --output idor_report.json
```

## IDORTester Class

### `__init__(base_url, user_a_token, user_b_token, verify_ssl)`
Creates two `requests.Session` objects with different Bearer tokens for cross-user testing.

### `test_horizontal_idor(endpoint_template, own_id, other_id, method) -> dict`
Accesses own resource then another user's resource with the same token. IDOR confirmed when both return 200 with different content.

### `test_vertical_idor(endpoint, method) -> dict`
Accesses admin-only endpoints with a regular user token. Status 200 indicates missing authorization.

### `test_id_enumeration(endpoint_template, id_range, method) -> dict`
Iterates over an ID range to discover valid objects. Returns count and sample IDs.

### `test_write_idor(endpoint_template, other_id, payload) -> dict`
Sends PUT with another user's ID to test write-based IDOR. Status 200/201/204 indicates vulnerability.

### `test_cross_session(endpoint_template, resource_id) -> dict`
Compares response hashes between two sessions for the same resource to detect missing authorization checks.

### `generate_report() -> dict`
Returns all accumulated findings with severity assessment.

## Output Schema

```json
{
  "target": "https://target.example.com",
  "total_findings": 2,
  "findings": [{"type": "horizontal", "endpoint": "/api/v1/users/{id}/profile", "vulnerable": true}],
  "severity": "High"
}
```
