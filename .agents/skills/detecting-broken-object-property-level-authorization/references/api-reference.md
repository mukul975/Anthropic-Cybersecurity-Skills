# API Reference: Detecting Broken Object Property Level Authorization

## OWASP API3:2023 Classification

| Category | Description |
|----------|-------------|
| Excessive Data Exposure | API returns more properties than client needs |
| Mass Assignment | API accepts more properties than intended |
| CWE-213 | Exposure of Sensitive Information Due to Incompatible Policies |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |

## Python requests Library

```python
import requests

# GET - test for excessive exposure
resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
resp.status_code  # 200, 401, 403
resp.json()       # parsed response body

# PUT - test for mass assignment
resp = requests.put(url, json={"role": "admin"}, headers=headers, timeout=10)

# PATCH - test for partial mass assignment
resp = requests.patch(url, json={"is_admin": True}, headers=headers, timeout=10)
```

## Sensitive Field Patterns

| Severity | Fields |
|----------|--------|
| Critical | password, password_hash, secret, token, api_key, private_key |
| High | ssn, credit_card, card_number, cvv, bank_account |
| Medium | salary, role, permissions, is_admin, session_id |
| Low | phone, address, date_of_birth, gender |

## Mass Assignment Test Payloads

```json
{"role": "admin"}
{"is_admin": true}
{"is_verified": true}
{"account_type": "premium"}
{"discount_rate": 100}
{"permissions": ["admin", "write", "delete"]}
```

## Burp Suite Extensions

```
# Autorize - test authorization across roles
# Param Miner - discover hidden parameters
# JSON Beautifier - inspect response properties
```

## CLI Usage

```bash
python agent.py --base-url https://api.example.com \
  --endpoint /api/v1/users/123 \
  --token "eyJhbGciOiJIUzI1NiJ9..." \
  --expected-fields id username name email \
  --test both --method PUT
```

## Mitigation Patterns

```python
# Allowlist serialization (Django REST Framework)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'name']  # explicit allowlist
        read_only_fields = ['id', 'role', 'is_admin']
```
