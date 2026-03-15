# API Reference: Implementing Passwordless Auth with Microsoft Entra

## Libraries

### msal (Microsoft Authentication Library)
- **Install**: `pip install msal`
- **Docs**: https://msal-python.readthedocs.io/
- `ConfidentialClientApplication()` -- App registration auth
- `acquire_token_for_client()` -- Client credentials flow

### Microsoft Graph API
- **Base**: `https://graph.microsoft.com/v1.0` and `/beta`
- **Docs**: https://learn.microsoft.com/en-us/graph/api/overview

## Authentication Methods Policy API

| Endpoint | Description |
|----------|-------------|
| `GET /policies/authenticationMethodsPolicy` | Full auth methods config |
| `GET /users/{id}/authentication/methods` | User's registered methods |
| `GET /users/{id}/authentication/fido2Methods` | FIDO2 keys for user |
| `GET /users/{id}/authentication/microsoftAuthenticatorMethods` | Authenticator setup |
| `GET /users/{id}/authentication/windowsHelloForBusinessMethods` | WHfB status |

## Conditional Access API

| Endpoint | Description |
|----------|-------------|
| `GET /identity/conditionalAccess/policies` | List CA policies |
| `GET /identity/conditionalAccess/authenticationStrength/policies` | Auth strength policies |

## Sign-In Logs API

| Endpoint | Description |
|----------|-------------|
| `GET /auditLogs/signIns` | Sign-in activity logs |
| Filter: `authenticationDetails/any(a:a/authenticationMethod eq 'FIDO2 security key')` |

## Authentication Method Types
- `fido2AuthenticationMethod` -- FIDO2 security keys
- `microsoftAuthenticatorAuthenticationMethod` -- Authenticator app
- `windowsHelloForBusinessAuthenticationMethod` -- Windows Hello
- `passwordAuthenticationMethod` -- Traditional password
- `phoneAuthenticationMethod` -- SMS/phone call (legacy)
- `emailAuthenticationMethod` -- Email OTP

## Required Graph Permissions
- `UserAuthenticationMethod.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`
- `User.Read.All`

## External References
- Entra Passwordless: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless
- FIDO2 Keys: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key
- Graph Auth Methods: https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethods-overview
- Conditional Access Auth Strength: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths
