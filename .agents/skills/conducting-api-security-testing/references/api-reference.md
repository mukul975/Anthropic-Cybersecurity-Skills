# API Reference: API Security Testing Agent

## Overview

Tests REST and GraphQL APIs for OWASP API Security Top 10 vulnerabilities including BOLA, BFLA, mass assignment, rate limiting, JWT bypass, and GraphQL introspection disclosure. For authorized penetration testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP requests to target APIs |

## CLI Usage

```bash
python agent.py --base-url https://api.target.com --token <jwt> \
  --low-priv-token <jwt> --graphql --output report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--base-url` | Yes | Target API base URL |
| `--token` | No | Auth bearer token for authenticated testing |
| `--low-priv-token` | No | Low-privilege token for BFLA testing |
| `--login-endpoint` | No | Login endpoint for rate limiting test (default: `/api/auth/login`) |
| `--graphql` | No | Test GraphQL introspection disclosure |
| `--output` | No | Output file (default: `api_security_report.json`) |

## Key Functions

### `test_bola(base_url, endpoint_template, id_field, valid_id, other_id, auth_token)`
Tests Broken Object Level Authorization by accessing another user's resource with own credentials.

### `test_bfla(base_url, admin_endpoints, low_priv_token)`
Tests admin endpoints with low-privilege tokens using GET, POST, DELETE methods.

### `test_mass_assignment(base_url, endpoint, auth_token, extra_fields)`
Sends undocumented fields (role, isAdmin) to update endpoints and verifies if they persist.

### `test_rate_limiting(base_url, endpoint, num_requests)`
Sends rapid requests to detect absence of rate limiting on authentication endpoints.

### `test_jwt_none_algorithm(base_url, endpoint, jwt_token)`
Forges JWT with `alg: none` to test for algorithm confusion vulnerabilities.

### `test_graphql_introspection(base_url, graphql_endpoint)`
Sends introspection query to check if full schema disclosure is enabled.

### `test_excessive_data_exposure(base_url, endpoint, auth_token, expected_fields)`
Compares API response fields against expected fields to identify over-exposure.

## OWASP API Top 10 Coverage

| OWASP ID | Vulnerability | Function |
|----------|--------------|----------|
| API1:2023 | Broken Object Level Authorization | `test_bola` |
| API3:2023 | Excessive Data Exposure | `test_excessive_data_exposure` |
| API4:2023 | Unrestricted Resource Consumption | `test_rate_limiting` |
| API5:2023 | Broken Function Level Authorization | `test_bfla` |
| API6:2023 | Mass Assignment | `test_mass_assignment` |
