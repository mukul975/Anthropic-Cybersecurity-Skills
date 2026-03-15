# OAuth 2.0 Authorization Flow Workflows

## Workflow 1: Authorization Code Flow with PKCE

```
Client                     Auth Server              Resource Server
  |                            |                         |
  |-- Generate code_verifier --|                         |
  |-- Compute code_challenge --|                         |
  |                            |                         |
  |--- AuthZ Request --------->|                         |
  |  (code_challenge, state)   |                         |
  |                            |-- User Authenticates -->|
  |                            |<- User Consents --------|
  |<-- AuthZ Code + state -----|                         |
  |                            |                         |
  |--- Token Request --------->|                         |
  |  (code + code_verifier)    |                         |
  |<-- Access + Refresh Token--|                         |
  |                            |                         |
  |--- API Request (Bearer) ---|------------------------>|
  |<-- API Response ---------- |<------------------------|
```

### Step-by-Step:
1. Client generates `code_verifier`: random 43-128 char string (A-Z, a-z, 0-9, -._~)
2. Client computes `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Client redirects to: `GET /authorize?response_type=code&client_id=xxx&redirect_uri=xxx&scope=xxx&state=RANDOM&code_challenge=xxx&code_challenge_method=S256`
4. User authenticates and consents at authorization server
5. Server redirects to: `redirect_uri?code=AUTH_CODE&state=RANDOM`
6. Client validates state matches original
7. Client exchanges code: `POST /token` with `grant_type=authorization_code&code=AUTH_CODE&code_verifier=xxx&redirect_uri=xxx`
8. Server validates SHA256(code_verifier) matches stored code_challenge
9. Server returns access_token, refresh_token, id_token (if OIDC)

## Workflow 2: Client Credentials Flow (Machine-to-Machine)

```
Service A                  Auth Server              Service B (API)
  |                            |                         |
  |--- Token Request --------->|                         |
  |  (client_id, secret, scope)|                         |
  |<-- Access Token -----------|                         |
  |                            |                         |
  |--- API Request (Bearer) ---|------------------------>|
  |<-- API Response ---------- |<------------------------|
```

### Step-by-Step:
1. Service registers with auth server (client_id + client_secret)
2. Service requests token: `POST /token` with `grant_type=client_credentials&scope=api:read`
3. Auth server validates client credentials
4. Auth server returns access_token (no refresh token, no user context)
5. Service calls API with `Authorization: Bearer ACCESS_TOKEN`

## Workflow 3: Token Refresh with Rotation

```
Client                     Auth Server
  |                            |
  |--- Refresh Request ------->|
  |  (refresh_token_v1)        |
  |<-- New Access Token -------|
  |<-- New Refresh Token (v2) -|
  |  (v1 invalidated)          |
  |                            |
  |--- Refresh Request ------->|
  |  (refresh_token_v2)        |
  |<-- New Access Token -------|
  |<-- New Refresh Token (v3) -|
  |                            |
  |--- THEFT: Reuse v1 ------->|
  |  (DETECTED: v1 reused)     |
  |<-- REVOKE ALL TOKENS ------|
```

### Rotation Detection:
- Each refresh token is single-use
- On reuse of an old refresh token, server detects theft
- All tokens in the grant chain are revoked
- User must re-authenticate

## Workflow 4: Device Authorization Grant

```
Device                     Auth Server              User (Browser)
  |                            |                         |
  |--- Device AuthZ Request -->|                         |
  |<-- device_code,            |                         |
  |    user_code,              |                         |
  |    verification_uri -------|                         |
  |                            |                         |
  |-- Display user_code ------>|                         |
  |   to user on screen        |                         |
  |                            |<-- User visits URI -----|
  |                            |<-- Enters user_code ----|
  |                            |<-- Authenticates -------|
  |                            |<-- Consents ------------|
  |                            |                         |
  |--- Poll Token Endpoint --->|                         |
  |  (device_code)             |                         |
  |<-- Access Token -----------|                         |
```

## Workflow 5: Token Revocation

### Steps:
1. Client sends revocation request: `POST /revoke` with `token=xxx&token_type_hint=refresh_token`
2. Auth server invalidates the token
3. If refresh token revoked, all associated access tokens also invalidated
4. Server returns 200 OK regardless of whether token was valid (prevents token fishing)

## Workflow 6: Security Incident - Token Compromise Response

### Steps:
1. Detect suspicious token usage (unusual IP, impossible travel)
2. Immediately revoke the compromised token via revocation endpoint
3. If refresh token compromised, revoke entire token family
4. Force re-authentication for affected user
5. Audit all API calls made with compromised token
6. Check for scope escalation attempts
7. Review authorization logs for the compromised session
8. Notify affected user and security team
