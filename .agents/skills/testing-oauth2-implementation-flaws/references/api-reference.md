# API Reference: Testing OAuth2 Implementation Flaws

## OAuth 2.0 Grant Types

| Grant Type | Use Case | Risk Level |
|------------|----------|------------|
| Authorization Code | Server-side apps | Low (with PKCE) |
| Authorization Code + PKCE | Mobile/SPA apps | Low |
| Implicit | Legacy SPAs | High (deprecated) |
| Client Credentials | Machine-to-machine | Medium |
| Resource Owner Password | Legacy migration | High |

## OAuth Attack Surface

| Attack | Severity | Vector |
|--------|----------|--------|
| Redirect URI bypass | Critical | Subdomain, path traversal, encoding |
| Missing state parameter | High | CSRF-based account linking |
| PKCE bypass | High | Authorization code interception |
| Scope escalation | High | Request unauthorized permissions |
| Code reuse | High | Replay authorization code |
| Token in URL fragment | Medium | Referer header leakage |
| Implicit flow | Medium | Token exposure in browser history |

## Redirect URI Bypass Techniques

| Technique | Example |
|-----------|---------|
| Subdomain append | `redirect.com.evil.com` |
| Path traversal | `redirect.com/../evil.com` |
| At-sign confusion | `redirect.com@evil.com` |
| Fragment bypass | `redirect.com%23@evil.com` |
| Query parameter | `redirect.com?next=evil.com` |
| HTTP downgrade | `http://` instead of `https://` |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP OAuth flow testing |
| `secrets` | stdlib | State/nonce generation |
| `urllib.parse` | stdlib | URL parameter encoding |
| `hashlib` | stdlib | PKCE code challenge |

## References

- OAuth 2.0 Security Best Practices: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- PortSwigger OAuth: https://portswigger.net/web-security/oauth
- RFC 6749: https://www.rfc-editor.org/rfc/rfc6749
- RFC 7636 (PKCE): https://www.rfc-editor.org/rfc/rfc7636
