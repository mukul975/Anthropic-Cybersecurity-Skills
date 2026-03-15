# API Reference: Testing Mobile API Authentication

## Common Mobile Auth Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| /api/v1/login | POST | Username/password authentication |
| /api/v1/register | POST | New account creation |
| /api/v1/token | POST | OAuth token exchange |
| /api/v1/refresh | POST | Token refresh flow |
| /api/v1/logout | POST | Session termination |
| /api/v1/verify-otp | POST | MFA code verification |
| /api/v1/me | GET | Current user profile |

## Mobile-Specific JWT Claims

| Claim | Purpose | Security Impact |
|-------|---------|-----------------|
| device_id / did | Bind token to device | Prevents token theft across devices |
| platform | iOS/Android identifier | Enables platform-specific policy |
| app_version | Client version tracking | Version-gated feature access |
| exp | Token expiration | Missing = permanent access |

## Test Categories

| Test | Severity | Description |
|------|----------|-------------|
| No auth access | Critical | Endpoints accessible without token |
| IDOR | Critical | Access other users' resources |
| Weak JWT secret | Critical | Brute-force HMAC signing key |
| Token reuse after logout | High | Token valid after logout |
| No rate limiting | High | Unlimited login attempts |
| Missing device binding | Medium | Token works on any device |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP API testing |
| `base64` | stdlib | JWT decoding |
| `hmac` | stdlib | HMAC signature verification |
| `hashlib` | stdlib | Hash functions for JWT |

## References

- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/
- OWASP API Security Top 10: https://owasp.org/API-Security/
- MASVS Authentication: https://mas.owasp.org/MASVS/05-MASVS-AUTH/
