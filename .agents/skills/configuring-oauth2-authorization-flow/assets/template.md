# OAuth 2.0 Authorization Flow Configuration Template

## Application Registration
| Field | Value |
|-------|-------|
| Application Name | |
| Client ID | |
| Client Type | [ ] Public [ ] Confidential |
| Grant Types | [ ] Authorization Code [ ] Client Credentials [ ] Refresh Token [ ] Device Code |
| PKCE Required | [ ] Yes (mandatory for OAuth 2.1) |

## Redirect URI Configuration
| Environment | URI | Status |
|-------------|-----|--------|
| Development | http://localhost:3000/callback | [ ] Registered |
| Staging | https://staging.example.com/callback | [ ] Registered |
| Production | https://app.example.com/callback | [ ] Registered |

**Rules:**
- Exact match only - no wildcards
- HTTPS required for non-localhost URIs
- Each URI must be explicitly registered

## Scope Design
| Scope | Description | Sensitivity |
|-------|-------------|-------------|
| openid | OpenID Connect identity | Low |
| profile | User profile information | Low |
| email | User email address | Low |
| read:users | Read user records | Medium |
| write:users | Modify user records | High |
| admin:settings | Modify system settings | Critical |

## Token Configuration
| Parameter | Value | Justification |
|-----------|-------|---------------|
| Access Token Lifetime | 15 minutes | Minimize window of exposure |
| Refresh Token Lifetime | 8 hours | Align with business hours |
| Refresh Token Rotation | Enabled | Detect token theft via reuse |
| Refresh Token Absolute Expiry | 24 hours | Force re-authentication daily |
| ID Token Lifetime | 5 minutes | Only used for initial authentication |
| Token Format | JWT (signed) | Enable stateless validation |
| Signing Algorithm | RS256 | Asymmetric verification |

## Security Checklist
- [ ] PKCE enforced for all authorization code flows
- [ ] Implicit grant disabled
- [ ] ROPC (password) grant disabled
- [ ] State parameter validated
- [ ] Exact redirect URI matching enforced
- [ ] Refresh token rotation enabled
- [ ] Token revocation endpoint active
- [ ] DPoP enabled for high-security APIs
- [ ] Consent screen configured for sensitive scopes
- [ ] Token introspection secured with authentication

## Client Authentication Methods
| Method | Use Case | Security Level |
|--------|----------|---------------|
| none | Public clients (SPA, mobile) | Requires PKCE |
| client_secret_basic | Server-side web apps | Medium |
| client_secret_post | Server-side web apps | Medium |
| private_key_jwt | High-security services | High |
| tls_client_auth | mTLS-capable services | High |

## Monitoring & Alerting
- [ ] Token issuance rate monitoring
- [ ] Failed authentication attempts tracking
- [ ] Refresh token reuse detection alerts
- [ ] Scope escalation attempt alerts
- [ ] Unusual client_id activity monitoring
- [ ] Geographic anomaly detection for token usage
