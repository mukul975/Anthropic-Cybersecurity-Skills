# SCIM Provisioning Implementation Checklist

## Project: _______________
## Date: _______________
## Engineer: _______________

## Pre-Implementation

- [ ] Okta tenant provisioned with admin access
- [ ] Application API supports user CRUD operations
- [ ] TLS certificate configured for SCIM endpoint
- [ ] Database schema supports SCIM user attributes
- [ ] Bearer token generated and securely stored

## SCIM Server Configuration

| Setting | Value |
|---------|-------|
| Base URL | `https://______/scim/v2` |
| Auth Method | Bearer Token / OAuth 2.0 |
| SCIM Version | 2.0 |
| Unique ID Field | userName |

## Attribute Mapping

| Okta Attribute | SCIM Attribute | Required | Notes |
|---------------|----------------|----------|-------|
| login | userName | Yes | |
| firstName | name.givenName | Yes | |
| lastName | name.familyName | Yes | |
| email | emails[0].value | Yes | |
| department | enterprise:department | No | |
| title | title | No | |

## Endpoint Testing Results

| Endpoint | Method | Status | Notes |
|----------|--------|--------|-------|
| /Users | POST | [ ] Pass | Create user |
| /Users | GET | [ ] Pass | List/filter users |
| /Users/{id} | GET | [ ] Pass | Get single user |
| /Users/{id} | PUT | [ ] Pass | Replace user |
| /Users/{id} | PATCH | [ ] Pass | Partial update |
| /Users/{id} | DELETE | [ ] Pass | Delete user |
| /Groups | POST | [ ] Pass | Create group |
| /Groups | GET | [ ] Pass | List groups |
| /Groups/{id} | PATCH | [ ] Pass | Update members |

## Okta Configuration

- [ ] SCIM app integration created
- [ ] Provisioning tab configured with base URL and token
- [ ] "To App" provisioning enabled (Create, Update, Deactivate)
- [ ] Attribute mappings verified
- [ ] Group Push configured (if needed)
- [ ] Test user assigned and provisioned successfully
- [ ] Test user unassigned and deprovisioned successfully

## Validation

- [ ] Okta SCIM validator test suite passed
- [ ] Error responses return correct SCIM error format
- [ ] Pagination works with startIndex and count parameters
- [ ] Filter on userName eq works correctly
- [ ] Deactivation sets active=false (soft delete)
- [ ] PATCH operations handle add/replace/remove

## Production Readiness

- [ ] SCIM endpoint uses production TLS certificate
- [ ] Bearer token rotated from development value
- [ ] Rate limiting configured on SCIM endpoints
- [ ] Monitoring and alerting set up for provisioning failures
- [ ] Provisioning error handling and retry logic tested
- [ ] Documentation updated with SCIM integration details
