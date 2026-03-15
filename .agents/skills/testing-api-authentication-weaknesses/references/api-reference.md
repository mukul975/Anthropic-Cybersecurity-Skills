# API Reference: Testing API Authentication Weaknesses

## JWT Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| alg:none | Critical | Signature verification bypassed |
| Weak HMAC secret | Critical | Brute-forceable signing key |
| No exp claim | High | Token never expires |
| Long TTL (>24h) | Medium | Extended token validity |
| Sensitive data in payload | High | PII in JWT claims |
| Missing iss/aud claims | Medium | Token scope ambiguity |

## OWASP API2:2023 Test Points

| Test | Category |
|------|----------|
| Unauthenticated endpoint access | Missing auth middleware |
| JWT alg:none bypass | Broken token validation |
| JWT secret brute-force | Weak cryptographic key |
| Token reuse after logout | Missing revocation |
| Refresh token rotation | Session management |
| Account enumeration | Information disclosure |
| Password policy bypass | Weak credential controls |

## Common JWT HMAC Secrets

| Secret | Type |
|--------|------|
| `secret` | Default |
| `your-256-bit-secret` | JWT.io example |
| `jwt_secret` | Convention |
| `changeme` | Placeholder |

## JWT Attack Tools

| Tool | Purpose |
|------|---------|
| jwt_tool | JWT testing with 12+ attack modes |
| hashcat -m 16500 | GPU JWT secret brute-force |
| Burp JWT Editor | Interactive JWT manipulation |
| Nuclei | Auth bypass templates |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP API calls |
| `base64` | stdlib | JWT decoding |
| `hmac` | stdlib | HMAC signature testing |
| `hashlib` | stdlib | Hash functions |

## References

- OWASP API Security Top 10: https://owasp.org/API-Security/
- JWT Best Practices RFC 8725: https://www.rfc-editor.org/rfc/rfc8725
- jwt_tool: https://github.com/ticarpi/jwt_tool
