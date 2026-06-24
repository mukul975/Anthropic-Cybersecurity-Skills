---
name: reviewing-jwt-implementation
description: >-
  Analyze JSON Web Tokens (JWT) for cryptographic weaknesses, algorithm confusion, 
  and sensitive information disclosure. Applicable to login mechanisms, API gateways, 
  and SSO (Single Sign-On) environments.
domain: cybersecurity
subdomain: web-application-security
tags: [jwt, authentication, cryptography, penetration-testing]
mitre_attack: [T1550.001, T1528]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Analyzing JWT Vulnerabilities

## When to Use

- When the application uses tokens for authentication or state management that begin with `eyJ` (Base64URL encoding of `{"alg"`).
- When you find JWTs in `Authorization: Bearer <token>` headers, Cookies, or LocalStorage.
- When evaluating API Gateways, OAuth callbacks, or internal service-to-service communication.
- When you need to assess the strength of HMAC secrets, algorithm implementation flaws, or claim validation logic.

## Prerequisites

- An interception proxy (Burp Suite, ZAP) equipped with JWT manipulation extensions (e.g., JSON Web Tokens extension).
- A wordlist of common JWT secrets (for HMAC offline brute-forcing).
- The ability to base64url decode and encode payloads manually or via scripts.

## Workflow

1. Initialize and execute the testing sequence.

```bash
# Verification block
echo test
```




### Step 1: Baseline Extraction and Decoding
1. Locate the JWT in HTTP traffic (headers, cookies, or body).
2. Decode the Base64URL header and payload without verifying the signature (e.g., using `jwt.io` locally or a CLI tool).
3. Record the algorithm (`alg`), expiration (`exp`, `nbf`, `iat`), and any sensitive claims (e.g., `role`, `user_id`, `email`, `isAdmin`).

### Step 2: Sensitive Information Disclosure
Review the decoded payload. Does it contain PII (Personally Identifiable Information) such as SSNs, internal IP addresses, or internal database IDs? JWT payloads are merely encoded, not encrypted, meaning anyone who intercepts the token can read them.

### Step 3: Cryptographic Weaknesses and Bypass Attempts
Attempt to manipulate the signature validation mechanism based on the `alg` declared in the header.

**Scenario A: None Algorithm (`alg=none`)**
1. Change the algorithm in the header to `none`.
2. Modify a claim in the payload (e.g., `"role": "admin"`).
3. Remove the signature entirely, leaving the trailing dot: `Header.Payload.`
4. Send the modified token to a protected endpoint.

**Scenario B: HMAC Weak Secret Brute-forcing (`alg=HS256/HS384/HS512`)**
1. Use an offline cracking tool (like `hashcat` or `jwt_tool`) with a common dictionary to guess the secret key.
2. If successful, use the discovered secret to sign a new token with elevated privileges and test it against the application.

**Scenario C: Algorithm Confusion (`alg=RS256` -> `HS256`)**
1. If the server expects an RSA public/private key pair (`RS256`) but does not explicitly whitelist the algorithm, it might trust the `alg` header in the token.
2. Retrieve the application's public key (often available at `/.well-known/jwks.json`).
3. Change the token header to `alg=HS256`.
4. Sign the modified payload using the *public key* as an *HMAC secret*.
5. If the server uses a flawed validation library, it will treat the public key as an HMAC secret and validate your forged token.

### Step 4: Verification and Replay
- Verify that expiration claims (`exp`) are actively enforced by waiting for a token to expire and replaying it.
- **Critical Requirement**: A vulnerability is only confirmed if the server actually *accepts* the forged/tampered token and grants access to protected resources. Simply generating a signed token is not enough if the backend database still rejects the user.

## Key Concepts

| Term | Definition |
|------|------------|
| **JWT (JSON Web Token)** | A compact, URL-safe means of representing claims to be transferred between two parties. Composed of Header, Payload, and Signature. |
| **HMAC (HS256)** | Symmetric cryptography where the same secret key is used to both sign and verify the token. |
| **RSA (RS256)** | Asymmetric cryptography where a private key signs the token, and a public key verifies it. |
| **Algorithm Confusion** | A vulnerability where an attacker tricks the server into verifying an asymmetric signature (RS256) using a symmetric algorithm (HS256), substituting the public key as the symmetric secret. |


## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - Token Length
**Context**: A JWT token is over 500 characters long. You assume the cryptographic key is very strong.
**Analysis**: Token length is determined by the size of the payload (the claims), not the strength of the secret key. A 1000-character JWT can still be signed with a 4-character weak secret like `test`.
**Action**: Proceed with offline brute-force attempts regardless of token length if the algorithm is HMAC.

### Scenario: Cross-System Differences
**Context**: You find that the main web application's session JWT is securely signed with `RS256`.
**Analysis**: You assume the entire ecosystem is secure. However, microservices or API gateways often use different signing mechanisms. The token used to refresh the session might use `HS256` with a weak secret.
**Action**: Test *every* unique token type and endpoint independently. Do not generalize security findings across different subsystems.

## Output Format

Document confirmed vulnerabilities with evidence of privilege escalation or data access:

```json
{
  "id": "jwt-001",
  "title": "JWT Weak Secret leading to Privilege Escalation",
  "severity": "critical",
  "cwe": "CWE-1212",
  "endpoint": "GET /api/v1/admin/dashboard",
  "status": "confirmed",
  "evidence": {
    "weak_secret_found": "secret123",
    "forged_token": "eyJhb... (payload with role: admin) ...signature",
    "execution_proof": "The forged token was successfully used to access the /admin/dashboard endpoint, which previously returned HTTP 403 Forbidden."
  },
  "description": "The application's HS256 JWT tokens are signed using a weak secret ('secret123'). This allows an attacker to forge a valid token with the 'admin' role and access restricted administrative endpoints."
}
```
