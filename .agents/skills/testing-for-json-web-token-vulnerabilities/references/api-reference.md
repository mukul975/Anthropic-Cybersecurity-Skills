# API Reference: Testing for JSON Web Token Vulnerabilities

## JWT Attack Types

| Attack | Severity | Description |
|--------|----------|-------------|
| alg:none bypass | Critical | Remove signature verification |
| Weak HMAC secret | Critical | Brute-force signing key |
| Algorithm confusion | Critical | RS256 -> HS256 with public key |
| kid injection | High | Path traversal/SQLi in kid |
| jku spoofing | High | Point JWKS to attacker server |
| Claim tampering | High | Modify role/sub without re-sign |
| Missing exp | High | Token never expires |

## JWT Structure

| Part | Content | Example |
|------|---------|---------|
| Header | Algorithm, type, kid | `{"alg":"HS256","typ":"JWT"}` |
| Payload | Claims (sub, exp, iat, iss) | `{"sub":"1001","role":"user"}` |
| Signature | HMAC or RSA signature | Base64url encoded |

## JWT Testing Tools

| Tool | Purpose |
|------|---------|
| jwt_tool | 12+ attack modes for JWT testing |
| hashcat -m 16500 | GPU JWT HMAC secret cracking |
| Burp JWT Editor | Interactive JWT manipulation |
| jwt.io | Online JWT decoder |
| john | CPU-based JWT secret cracking |

## Standard Claims

| Claim | Required | Purpose |
|-------|----------|---------|
| iss | Yes | Issuer identifier |
| sub | Yes | Subject (user ID) |
| aud | Yes | Intended audience |
| exp | Yes | Expiration time |
| iat | Recommended | Issued at time |
| nbf | Optional | Not before time |
| jti | Optional | JWT ID (replay prevention) |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `base64` | stdlib | JWT encoding/decoding |
| `hmac` | stdlib | HMAC signature generation |
| `hashlib` | stdlib | Hash functions |
| `json` | stdlib | JSON parsing |
| `requests` | >=2.28 | Token testing against APIs |

## References

- jwt_tool: https://github.com/ticarpi/jwt_tool
- PortSwigger JWT: https://portswigger.net/web-security/jwt
- RFC 7519: https://www.rfc-editor.org/rfc/rfc7519
