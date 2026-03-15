# API Reference: Implementing Identity Governance with SailPoint

## SailPoint IdentityNow V3 API

```python
import requests
headers = {"Authorization": "Bearer <token>"}
base = "https://TENANT.api.identitynow.com"

identities = requests.get(f"{base}/v3/search/identities", headers=headers).json()
profiles = requests.get(f"{base}/v3/access-profiles", headers=headers).json()
campaigns = requests.get(f"{base}/v3/campaigns", headers=headers).json()
```

## Key API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v3/search/identities` | GET | Search identities |
| `/v3/access-profiles` | GET | List access profiles |
| `/v3/campaigns` | GET | Certification campaigns |
| `/v3/roles` | GET | List roles |
| `/v3/sources` | GET | List identity sources |
| `/v3/accounts` | GET | List accounts |

## Identity Lifecycle Events

| Event | Trigger | SLA |
|-------|---------|-----|
| Joiner | HR new hire | 24 hours |
| Mover | Department/role change | 48 hours |
| Leaver | Termination | 1 hour |

## SOD Policy Types

| Type | Example | Risk |
|------|---------|------|
| Toxic combination | AP + AR | HIGH |
| Privileged conflict | Admin + Auditor | CRITICAL |
| Regulatory | Trade execution + Compliance | CRITICAL |

## Certification Campaign Status

| Status | Action Needed |
|--------|--------------|
| STAGED | Not yet started |
| ACTIVE | In progress |
| COMPLETED | All decisions made |
| OVERDUE | Past deadline - escalate |

### References

- SailPoint IdentityNow API: https://developer.sailpoint.com/docs/api/v3
- SailPoint IIQ: https://community.sailpoint.com/
- NIST 800-53 AC-2: Account Management
