# API Reference: Managing Cloud Identity with Okta

## Okta Users API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/users` | GET | List all users with status and profile data |
| `/api/v1/users/{userId}` | GET | Get user profile and enrollment status |
| `/api/v1/users/{userId}/factors` | GET | List enrolled MFA factors for a user |
| `/api/v1/users/{userId}/lifecycle/deactivate` | POST | Deactivate a user account |
| `/api/v1/users/{userId}/lifecycle/suspend` | POST | Suspend a user account |

## Okta Applications API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/apps` | GET | List all application integrations |
| `/api/v1/apps/{appId}` | GET | Get application SSO config (SAML/OIDC) |
| `/api/v1/apps/{appId}/users` | GET | List users assigned to an application |
| `/api/v1/apps/{appId}/groups` | GET | List groups assigned to an application |

## Okta Policies API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/policies?type=OKTA_SIGN_ON` | GET | List sign-on policies |
| `/api/v1/policies?type=MFA_ENROLL` | GET | List MFA enrollment policies |
| `/api/v1/policies/{policyId}/rules` | GET | List rules within a policy |

## Okta Groups API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/groups` | GET | List all groups |
| `/api/v1/groups/{groupId}/users` | GET | List members of a group |

## Key Libraries

- **okta** (`pip install okta`): Official Okta Python SDK with async support
- **okta-jwt-verifier**: Verify Okta-issued JWT tokens
- **requests**: Fallback HTTP client for direct Okta REST API calls

## Configuration

| Variable | Description |
|----------|-------------|
| `OKTA_ORG_URL` | Okta organization URL (e.g., `https://company.okta.com`) |
| `OKTA_API_TOKEN` | API token with `okta.users.read`, `okta.apps.read` scopes |
| `OKTA_CLIENT_ID` | OAuth app client ID for service-to-service auth |

## Rate Limits

| Endpoint Category | Rate Limit |
|-------------------|------------|
| `/api/v1/users` | 600 requests/minute |
| `/api/v1/apps` | 600 requests/minute |
| `/api/v1/logs` | 120 requests/minute |

## References

- [Okta API Reference](https://developer.okta.com/docs/reference/api/)
- [Okta Python SDK](https://github.com/okta/okta-sdk-python)
- [Okta Security Best Practices](https://developer.okta.com/docs/concepts/security-best-practices/)
