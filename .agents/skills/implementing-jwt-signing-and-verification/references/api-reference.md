# API Reference: Implementing JWT Signing and Verification

## PyJWT Library

```python
import jwt
# Sign with HS256
token = jwt.encode({"sub": "user1", "exp": time.time() + 3600}, "secret", algorithm="HS256")
# Verify
payload = jwt.decode(token, "secret", algorithms=["HS256"])
# Sign with RS256
token = jwt.encode(payload, private_key, algorithm="RS256")
payload = jwt.decode(token, public_key, algorithms=["RS256"])
```

## JWT Algorithms

| Algorithm | Type | Key Size | Use Case |
|-----------|------|----------|----------|
| HS256 | HMAC | 256-bit secret | Internal services |
| RS256 | RSA | 2048+ bit | Public verification |
| ES256 | ECDSA | P-256 curve | Compact tokens |
| EdDSA | Ed25519 | 256-bit | High performance |
| none | - | - | NEVER use in production |

## Standard JWT Claims (RFC 7519)

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | String | Issuer |
| `sub` | String | Subject |
| `aud` | String/Array | Audience |
| `exp` | NumericDate | Expiration time |
| `nbf` | NumericDate | Not before |
| `iat` | NumericDate | Issued at |
| `jti` | String | JWT ID (unique) |

## Common JWT Attacks

| Attack | Description | Mitigation |
|--------|-------------|-----------|
| Algorithm confusion | Switch RS256 to HS256 | Explicit algorithm allowlist |
| none algorithm | Remove signature | Reject alg=none |
| JKU/JWK injection | Inject attacker key | Ignore JKU/JWK headers |
| Token replay | Reuse valid token | Use jti + short exp |

### References

- RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- PyJWT: https://pyjwt.readthedocs.io/
- jose (JavaScript): https://github.com/panva/jose
- JWT.io Debugger: https://jwt.io/
