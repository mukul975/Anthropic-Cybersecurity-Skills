# JWT Implementation Template

## Algorithm Selection Guide

| Use Case | Recommended Algorithm | Reason |
|----------|----------------------|--------|
| Single server | HS256 | Simple, fast, shared secret |
| Microservices | RS256 / ES256 | Asymmetric, verify without secret |
| Mobile/IoT | ES256 | Small key/signature size |
| High performance | EdDSA | Fastest asymmetric signing |

## JWT Claims Checklist

- [ ] `sub` - Subject (user ID)
- [ ] `iss` - Issuer (your app identifier)
- [ ] `aud` - Audience (intended recipient)
- [ ] `exp` - Expiration (short-lived: 15 min access, 7 day refresh)
- [ ] `nbf` - Not before (prevents premature use)
- [ ] `iat` - Issued at (token creation time)
- [ ] `jti` - JWT ID (unique, for revocation)

## Security Checklist

- [ ] Algorithm allowlist enforced (never accept unknown alg)
- [ ] `alg: none` explicitly rejected
- [ ] Short expiration (access: 15 min, refresh: 7 days)
- [ ] Issuer and audience validation enabled
- [ ] Secrets >= 256 bits for HMAC algorithms
- [ ] RSA keys >= 2048 bits
- [ ] Tokens stored securely on client (httpOnly cookies preferred)
- [ ] Token refresh mechanism implemented
- [ ] Token revocation mechanism available (blacklist/JTI check)
