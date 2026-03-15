# Workflows - JWT Signing and Verification

## Workflow 1: Token Issuance

```
[Authentication Request] (username + password)
      |
[Validate Credentials]
      |
[Build JWT Claims]:
  - sub: user ID
  - iss: issuer URL
  - aud: audience
  - exp: expiration (now + 15 min)
  - iat: issued at
  - jti: unique token ID
      |
[Sign with Private Key / Secret]
(RS256 / ES256 / HS256)
      |
[Return: access_token + refresh_token]
```

## Workflow 2: Token Verification

```
[Incoming Request with Bearer Token]
      |
[Extract Token from Authorization Header]
      |
[Decode Header (without verification)]
[Check alg against allowlist]
      |
[Verify Signature]
(using public key / shared secret)
      |
[Validate Claims]:
  - exp: not expired
  - nbf: not before current time
  - iss: expected issuer
  - aud: expected audience
      |
[Accept / Reject Request]
```

## Workflow 3: Key Rotation

```
[Generate New Signing Key]
      |
[Add to JWK Set with unique kid]
      |
[Update /.well-known/jwks.json]
(new key + old key)
      |
[New tokens signed with new key]
[Old tokens still verify with old key]
      |
[After grace period: remove old key]
```
