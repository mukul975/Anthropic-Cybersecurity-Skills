---
name: configuring-oauth2-authorization-flow
description: Configure secure OAuth 2.0 authorization flows including Authorization Code with PKCE, Client Credentials, and Device Authorization Grant. This skill covers flow selection, PKCE implementation, token 
domain: cybersecurity
subdomain: identity-access-management
tags: [iam, identity, access-control, authentication, authorization, oauth2, oidc, pkce]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Configuring OAuth 2.0 Authorization Flow

## Overview
Configure secure OAuth 2.0 authorization flows including Authorization Code with PKCE, Client Credentials, and Device Authorization Grant. This skill covers flow selection, PKCE implementation, token lifecycle management, scope design, and alignment with OAuth 2.1 security requirements.

## Objectives
- Implement Authorization Code flow with PKCE for public and confidential clients
- Configure Client Credentials flow for machine-to-machine communication
- Design least-privilege scope hierarchies
- Implement secure token storage, refresh, and revocation
- Apply OAuth 2.1 best practices and RFC 9700 security recommendations
- Validate token integrity and prevent common OAuth attacks

## Key Concepts

### OAuth 2.0 Grant Types
1. **Authorization Code + PKCE**: Recommended for all client types (web, mobile, SPA). PKCE is mandatory in OAuth 2.1.
2. **Client Credentials**: Machine-to-machine authentication without user context.
3. **Device Authorization Grant (RFC 8628)**: For input-constrained devices (smart TVs, CLI tools).
4. **Refresh Token**: Long-lived token to obtain new access tokens without re-authentication.

### PKCE (Proof Key for Code Exchange)
PKCE (RFC 7636) prevents authorization code interception attacks:
1. Client generates random `code_verifier` (43-128 characters, unreserved URI chars)
2. Client computes `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Authorization request includes `code_challenge` and `code_challenge_method=S256`
4. Token request includes original `code_verifier`
5. Server validates `SHA256(code_verifier)` matches stored `code_challenge`

### Token Types
- **Access Token**: Short-lived (5-60 min), bearer or DPoP-bound
- **Refresh Token**: Long-lived, single-use with rotation
- **ID Token (OIDC)**: JWT containing user identity claims

## Implementation Steps

### Step 1: Authorization Code Flow with PKCE
1. Generate cryptographically random code_verifier (min 43 chars)
2. Compute code_challenge using S256 method
3. Redirect user to authorization endpoint with parameters:
   - response_type=code
   - client_id, redirect_uri, scope, state
   - code_challenge, code_challenge_method=S256
4. User authenticates and consents
5. Authorization server redirects with authorization code
6. Exchange code + code_verifier for tokens at token endpoint
7. Validate state parameter matches original value

### Step 2: Scope Design
- Define granular scopes: `read:users`, `write:orders`, `admin:settings`
- Follow least-privilege: request minimum scopes needed
- Implement scope validation on resource server
- Document scope hierarchy and consent requirements

### Step 3: Token Security
- Store tokens securely (httpOnly cookies for web, keychain for mobile)
- Implement token refresh with rotation (one-time-use refresh tokens)
- Set appropriate expiration: access tokens 5-15 min, refresh tokens 8-24 hrs
- Enable DPoP (Demonstration of Proof-of-Possession) for sender-constrained tokens
- Implement token revocation endpoint

### Step 4: Client Credentials Flow
1. Register service client with client_id and client_secret
2. Request token: POST /oauth/token with grant_type=client_credentials
3. Include scope for required permissions
4. Store client_secret securely (vault, env vars, not code)
5. Implement certificate-based client authentication for higher assurance

### Step 5: Security Hardening
- Enforce PKCE for all authorization code flows
- Use exact redirect URI matching (no wildcards)
- Implement CSRF protection with state parameter
- Enable refresh token rotation and revocation on reuse detection
- Apply RFC 9700 security best practices
- Block implicit grant and ROPC (removed in OAuth 2.1)

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Access Control | AC-3 | Token-based access enforcement |
| Authentication | IA-5 | Client credential management |
| Session Management | SC-23 | Token lifecycle management |
| Audit | AU-3 | Log all token issuance and revocation |
| Cryptographic Protection | SC-13 | PKCE and token signing |

## Common Pitfalls
- Using implicit grant (removed in OAuth 2.1) instead of authorization code + PKCE
- Storing tokens in localStorage (XSS vulnerable) instead of httpOnly cookies
- Not validating state parameter enabling CSRF attacks
- Using wildcard redirect URIs allowing open redirect exploitation
- Not implementing refresh token rotation allowing token theft persistence

## Verification
- [ ] Authorization Code + PKCE flow completes successfully
- [ ] PKCE code_challenge validated at token endpoint
- [ ] State parameter prevents CSRF
- [ ] Access tokens expire within configured lifetime
- [ ] Refresh token rotation issues new refresh token each use
- [ ] Token revocation invalidates both access and refresh tokens
- [ ] Client Credentials flow works for service-to-service calls
- [ ] Scopes correctly enforced at resource server
