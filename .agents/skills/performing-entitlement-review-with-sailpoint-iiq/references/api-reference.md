# API Reference: Entitlement Review with SailPoint IdentityIQ

## SailPoint IdentityIQ REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/identityiq/scim/v2/Users` | GET | List identities with entitlements and roles |
| `/identityiq/scim/v2/Users/{id}` | GET | Get identity details including accounts and entitlements |
| `/identityiq/scim/v2/Certifications` | GET | List certification campaigns with filter support |
| `/identityiq/scim/v2/Certifications/{id}/items` | GET | Get certification items for a campaign |
| `/identityiq/rest/certifications/{id}/statistics` | GET | Retrieve campaign completion statistics |
| `/identityiq/rest/identities/{id}/policyViolations` | GET | Check SOD policy violations for an identity |
| `/identityiq/rest/certifications/{id}/items/{itemId}` | POST | Submit approve/revoke decision on a cert item |

## Authentication

SailPoint IIQ REST API uses HTTP Basic Authentication. All requests require `Content-Type: application/json`.

```
Authorization: Basic base64(username:password)
```

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `filter` | string | GET /Certifications | SCIM filter expression (e.g., `phase eq "Active"`) |
| `attributes` | string | GET /Users/{id} | Comma-separated attributes to include |
| `decision` | string | POST /items/{id} | Certification decision: `Approve`, `Revoke`, `Mitigate` |
| `comments` | string | POST /items/{id} | Reviewer comments for audit trail |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP client for SailPoint REST API calls |

## References

- SailPoint IdentityIQ REST API Guide: https://documentation.sailpoint.com/identityiq/
- SailPoint SCIM 2.0 API: https://documentation.sailpoint.com/identityiq/help/scimrest/
- SailPoint Certification API: https://community.sailpoint.com/
- SOD Policy Configuration: https://documentation.sailpoint.com/identityiq/help/policies/
