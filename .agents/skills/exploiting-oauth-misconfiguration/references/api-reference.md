# API Reference: OAuth Misconfiguration Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for OAuth flow testing |

## CLI Usage

```bash
python scripts/agent.py \
  --url https://auth.example.com \
  --client-id APP_CLIENT_ID \
  --redirect-uri https://app.example.com/callback \
  --output oauth_report.json
```

## Functions

### `discover_oidc_config(base_url) -> dict`
Fetches `/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server`.

### `test_redirect_uri_bypasses(auth_endpoint, client_id, legitimate_uri) -> list`
Tests 10 redirect_uri manipulation techniques: subdomain hijack, path traversal, case variation, protocol downgrade, CRLF injection.

### `test_state_parameter(auth_endpoint, client_id, redirect_uri) -> dict`
Submits authorization request without `state` to check CSRF protection.

### `test_pkce_requirement(auth_endpoint, client_id, redirect_uri) -> dict`
Tests whether `code_challenge` parameter is required. Generates S256 challenge for comparison.

### `test_code_reuse(token_endpoint, auth_code, client_id, client_secret, redirect_uri) -> dict`
Exchanges an authorization code twice to check single-use enforcement.

### `test_scope_escalation(auth_endpoint, client_id, redirect_uri) -> dict`
Requests elevated scopes (`admin`, `write`, `delete`) to test scope validation.

### `run_assessment(config, client_id, redirect_uri) -> dict`
Orchestrates all tests and compiles findings.

## OAuth Endpoints Tested

| Endpoint | Source | Test |
|----------|--------|------|
| `authorization_endpoint` | OIDC config | Redirect URI, state, PKCE, scope |
| `token_endpoint` | OIDC config | Code reuse, scope escalation |

## Output Schema

```json
{
  "oidc_config": {"authorization_endpoint": "...", "token_endpoint": "..."},
  "redirect_uri_tests": [{"redirect_uri": "https://evil.com", "accepted": false}],
  "state_parameter": {"csrf_risk": false},
  "pkce": {"pkce_required": true},
  "findings": []
}
```
