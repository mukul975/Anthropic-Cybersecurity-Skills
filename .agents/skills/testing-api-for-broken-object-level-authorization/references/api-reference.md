# API Reference: Testing API for Broken Object Level Authorization

## BOLA Test Types

| Test | Method | Severity |
|------|--------|----------|
| Horizontal read | GET victim's resource with attacker token | High |
| Horizontal write | PATCH/PUT victim's resource | Critical |
| Horizontal delete | DELETE victim's resource | Critical |
| ID enumeration | Sequential/predictable ID access | High |
| Method bypass | Different HTTP methods on same resource | High |
| Batch request | Include victim IDs in batch endpoint | High |
| Nested resource | Access child via parent swap | High |

## Object ID Types

| Type | Example | Predictability |
|------|---------|---------------|
| Sequential integer | `/orders/1042` | High |
| UUID v4 | `/orders/550e8400-...` | Low |
| Encoded/base64 | `/orders/MTAwMg==` | Medium |
| Composite | `/users/42/orders/1042` | High |
| Slug | `/profiles/john-doe` | Medium |

## OWASP API1:2023 Checks

| Check | Description |
|-------|-------------|
| Per-object authorization | Every object access checks ownership |
| Data-layer enforcement | WHERE user_id = authenticated_user.id |
| Rate limiting | Slow enumeration attempts |
| UUID over sequential | Reduce predictability |
| Batch endpoint auth | Validate all IDs in arrays |

## Automated Tools

| Tool | Purpose |
|------|---------|
| Autorize (Burp) | Automated BOLA detection |
| OWASP ZAP Access Control | Authorization boundary testing |
| ffuf | ID enumeration at scale |
| Postman | Manual BOLA testing |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP API calls |
| `json` | stdlib | Response parsing |

## References

- OWASP API Security: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- Autorize: https://github.com/Quitten/Autorize
