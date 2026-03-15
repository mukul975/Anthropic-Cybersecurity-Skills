# OAuth 2.0 Authorization Flow — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | HTTP client for OAuth endpoints |
| authlib | `pip install authlib` | Full OAuth 2.0 / OIDC client library |
| PyJWT | `pip install PyJWT[crypto]` | JWT token validation and inspection |

## OIDC Discovery Endpoint

```
GET {issuer}/.well-known/openid-configuration
```

Returns: authorization_endpoint, token_endpoint, jwks_uri, supported grant types, scopes.

## OAuth 2.0 Grant Types

| Grant Type | Use Case | Security |
|------------|----------|----------|
| authorization_code | Server-side apps | Recommended with PKCE |
| client_credentials | Machine-to-machine | Service accounts only |
| implicit | (DEPRECATED) SPAs | Avoid — tokens in URL fragment |
| password | (DEPRECATED) Legacy | Avoid — credentials exposed to client |
| urn:ietf:params:oauth:grant-type:device_code | IoT/CLI | Approved for limited-input devices |

## Security Best Practices

| Practice | RFC |
|----------|-----|
| PKCE (Proof Key for Code Exchange) | RFC 7636 |
| Token Binding | RFC 8471 |
| DPoP (Demonstrating Proof of Possession) | RFC 9449 |
| Sender-Constrained Tokens | OAuth 2.0 Security BCP |

## External References

- [RFC 6749 OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [authlib Documentation](https://docs.authlib.org/)
