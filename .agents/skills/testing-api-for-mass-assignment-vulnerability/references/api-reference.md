# API Reference: Testing API for Mass Assignment Vulnerability

## Privilege Field Categories

| Category | Example Fields | Impact |
|----------|---------------|--------|
| Role elevation | role, userRole, account_type | Admin access |
| Admin flags | isAdmin, is_superuser | Full privileges |
| Permissions | permissions, scopes, groups | Arbitrary access |
| Account status | verified, is_active | Bypass verification |
| Financial | balance, credit, discount, price | Monetary fraud |
| Ownership | user_id, owner_id | Data theft |
| Internal | debug, is_featured | Hidden features |

## Framework-Specific Payloads

| Framework | Payload Pattern |
|-----------|----------------|
| Rails/ActiveRecord | `{"user": {"role": "admin"}}` |
| Django REST | `{"is_staff": true, "is_superuser": true}` |
| Express/Mongoose | `{"$set": {"role": "admin"}}` |
| Spring Boot | `{"authorities": [{"authority": "ROLE_ADMIN"}]}` |

## OWASP API3:2023 Mitigations

| Mitigation | Description |
|-----------|-------------|
| DTO/Input Schema | Explicit allowed fields per endpoint |
| Strong parameters | Framework allowlist (Rails) |
| Serializer fields | Django REST serializer definition |
| Property filter | Drop unknown fields before binding |

## Test Tools

| Tool | Purpose |
|------|---------|
| Burp Repeater | Manual parameter injection |
| Param Miner (Burp) | Hidden parameter discovery |
| Arjun | Automated parameter fuzzing |
| Postman | Request body manipulation |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP API calls |
| `json` | stdlib | Payload construction |

## References

- OWASP API3:2023: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- Param Miner: https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
