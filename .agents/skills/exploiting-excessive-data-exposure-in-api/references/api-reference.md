# API Reference: Excessive Data Exposure (OWASP API3)

## OWASP API3:2023 — Broken Object Property Level Authorization

### Description
API returns more data than the client needs. Sensitive fields like passwords,
tokens, internal IDs, or PII are included in responses without filtering.

## Sensitive Field Categories

| Category | Examples |
|----------|----------|
| Credentials | password, secret, token, api_key |
| PII | ssn, date_of_birth, credit_card |
| Internal | internal_id, debug_info, stack_trace |
| Financial | salary, bank_account, routing_number |

## PII Detection Regex Patterns

| Type | Pattern |
|------|---------|
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |
| SSN | `\d{3}-\d{2}-\d{4}` |
| Credit Card | `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` |
| Phone | `\+?1?\d{10,15}` |
| IP Address | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` |

## Testing Methodology

### Step 1: Compare Response to Documentation
```bash
# Get actual response
curl -s https://api.target.com/users/me | jq 'keys'

# Compare with OpenAPI spec expected fields
```

### Step 2: Check for Sensitive Fields
```python
sensitive = ["password", "token", "ssn", "secret"]
for field in response_json:
    if any(s in field.lower() for s in sensitive):
        print(f"EXPOSED: {field}")
```

### Step 3: Test Different Roles
```bash
# As regular user, check if admin fields returned
curl -H "Authorization: Bearer $USER_TOKEN" \
     https://api.target.com/users/123 | jq '.role, .permissions'
```

## Python requests

### Fetch and Analyze
```python
resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
data = resp.json()
```

## Remediation Approaches

| Approach | Description |
|----------|-------------|
| Response filtering | Only return fields client needs |
| GraphQL field selection | Let client specify fields |
| View models / DTOs | Map internal model to public API |
| Role-based serialization | Different fields per role |

## Tools

### Postman Collection Runner
Automate response schema validation across endpoints.

### OWASP ZAP — Passive Scanner
Detects sensitive data in responses automatically.

### Swagger/OpenAPI Diff
```bash
openapi-diff expected-spec.yaml actual-responses.yaml
```
