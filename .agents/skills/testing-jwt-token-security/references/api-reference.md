# API Reference: Testing JWT Token Security

## PyJWT Library

### Installation
```bash
pip install PyJWT
```

### Encoding (Creating Tokens)
```python
import jwt
token = jwt.encode(payload, secret, algorithm="HS256")
```

### Decoding
```python
# Without verification (for analysis)
payload = jwt.decode(token, options={"verify_signature": False})

# With verification
payload = jwt.decode(token, secret, algorithms=["HS256"])
```

### Supported Algorithms
| Algorithm | Type | Description |
|-----------|------|-------------|
| `HS256` | HMAC | SHA-256 symmetric signing |
| `HS384` | HMAC | SHA-384 symmetric signing |
| `HS512` | HMAC | SHA-512 symmetric signing |
| `RS256` | RSA | SHA-256 asymmetric signing |
| `RS384` | RSA | SHA-384 asymmetric signing |
| `ES256` | ECDSA | P-256 curve signing |

## JWT Attack Types
| Attack | Description | Severity |
|--------|-------------|----------|
| Algorithm None | Set alg to "none", remove signature | Critical |
| Algorithm Confusion | Switch RS256 to HS256, sign with public key | Critical |
| HMAC Brute Force | Crack weak signing secrets | Critical |
| JKU Injection | Point JWK Set URL to attacker server | Critical |
| KID Injection | SQL injection or path traversal in Key ID | Critical |
| Claim Tampering | Modify role/sub claims after key compromise | High |
| Expired Token Reuse | Use tokens past expiration | High |
| No Revocation | Tokens valid after logout/password change | High |

## JWT Structure
```
Header.Payload.Signature
base64url({"alg":"HS256","typ":"JWT"}).base64url({"sub":"1","role":"user"}).HMACSHA256(...)
```

## Standard Claims
| Claim | Description |
|-------|-------------|
| `iss` | Token issuer |
| `sub` | Subject (user identifier) |
| `aud` | Intended audience |
| `exp` | Expiration time (Unix timestamp) |
| `nbf` | Not valid before time |
| `iat` | Issued at time |
| `jti` | Unique token identifier |

## References
- PyJWT docs: https://pyjwt.readthedocs.io/
- jwt_tool: https://github.com/ticarpi/jwt_tool
- JWT attacks: https://portswigger.net/web-security/jwt
- RFC 7519 (JWT): https://www.rfc-editor.org/rfc/rfc7519
