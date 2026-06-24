---
name: reviewing-cors-security-policies
description: >-
  Detect Cross-Origin Resource Sharing (CORS) misconfigurations. Evaluates endpoints 
  for unsafe Access-Control-Allow-Origin reflections, null origin trust, wildcard usage 
  with credentials, and over-permissive preflight responses.
domain: cybersecurity
subdomain: web-application-security
tags: [cors, cross-origin, api-security, penetration-testing]
mitre_attack: [T1189]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Analyzing CORS Misconfigurations

## When to Use

- When an endpoint returns CORS headers such as `Access-Control-Allow-Origin` (ACAO).
- When assessing Web APIs, decoupled frontend/backend architectures, or API gateways.
- When you need to determine if an attacker can read sensitive data across origins via browser XMLHttpRequests or Fetch API.

## Prerequisites

- An interception proxy (Burp Suite, ZAP).
- Understanding of HTTP request headers (specifically `Origin`) and CORS response headers.
- Access to an authenticated session to verify if credentials can be passed cross-origin to read sensitive data.

## Workflow

1. Initialize and execute the testing sequence.

```bash
# Verification block
echo test
```




### Step 1: Baseline Request
1. Send a request to the target endpoint without an `Origin` header to establish the baseline response.
2. Send the same request with a trusted `Origin` header (e.g., `Origin: https://target.com`). Record the `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC) response headers.

### Step 2: Origin Reflection & Bypass Testing
Manipulate the `Origin` header to identify if the server dynamically reflects it or uses a weak whitelist:
- **Malicious Origin**: `Origin: https://evil.example.com`
- **Null Origin**: `Origin: null` (Used by sandboxed iframes).
- **Prefix Bypass**: `Origin: https://target.com.evil.com`
- **Suffix Bypass**: `Origin: https://evil-target.com`
- **Protocol Bypass**: `Origin: http://target.com` (Downgrade to HTTP).
- **Port Variation**: `Origin: https://target.com:9999`

### Step 3: Assessing the Impact
If the server reflects the malicious origin in the ACAO header, verify the following:
1. **Credentials**: Does the response include `Access-Control-Allow-Credentials: true`? If yes, the attacker can force the victim's browser to attach cookies/sessions to the cross-origin request.
2. **Sensitive Data**: Does the endpoint actually return sensitive data? (e.g., PII, API keys, CSRF tokens). A CORS misconfiguration on a public, non-sensitive endpoint (like loading a public logo) is informational, not a vulnerability.

### Step 4: Preflight Validation (OPTIONS)
Send an `OPTIONS` request with a malicious `Origin` to simulate a CORS preflight. Check if the server responds with overly permissive `Access-Control-Allow-Methods` or `Access-Control-Allow-Headers` (e.g., allowing custom headers like `X-Admin-Access`).

## Key Concepts

| Term | Definition |
|------|------------|
| **CORS (Cross-Origin Resource Sharing)** | A security mechanism implemented by browsers that allows servers to specify which origins are permitted to read their responses. |
| **Origin Reflection** | A dangerous anti-pattern where the server dynamically reads the `Origin` header from the request and copies it directly into the `Access-Control-Allow-Origin` response header, effectively allowing *any* site to access it. |
| **Preflight Request** | An `OPTIONS` request sent by the browser before the actual request to verify if the server permits the cross-origin cross-method/cross-header request. |


## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - Wildcard ACAO
**Context**: An endpoint returns `Access-Control-Allow-Origin: *`.
**Analysis**: The `*` wildcard explicitly forbids the use of `Access-Control-Allow-Credentials: true`. Browsers will not attach cookies to requests aimed at wildcard CORS endpoints.
**Action**: Determine if the endpoint relies on cookies for authentication. If it doesn't, and it contains sensitive data, it might still be vulnerable (e.g., if the user is authenticated via internal IP whitelisting instead of cookies). If it's just public data, it's not a vulnerability.

### Scenario: False Negative - Null Origin
**Context**: The application strictly validates `https://evil.com` and rejects it.
**Analysis**: Developers often mistakenly whitelist the string `null` in their CORS configurations to support local development or specific edge cases.
**Action**: Test `Origin: null`. An attacker can exploit this by hosting an HTML payload inside a `<iframe sandbox="allow-scripts allow-top-navigation">`, which causes the browser to send a `null` Origin.

## Output Format

Document confirmed vulnerabilities with evidence of the reflected headers and the sensitivity of the exposed data:

```json
{
  "id": "cors-001",
  "title": "CORS Misconfiguration leading to Sensitive Data Exposure",
  "severity": "high",
  "cwe": "CWE-942",
  "endpoint": "GET /api/v1/user/profile",
  "status": "confirmed",
  "evidence": {
    "request_origin": "https://evil.com",
    "response_headers": "Access-Control-Allow-Origin: https://evil.com\\nAccess-Control-Allow-Credentials: true",
    "execution_proof": "By crafting an XHR request from https://evil.com, the browser successfully read the victim's email and home address from the /profile endpoint using the victim's active session cookie."
  },
  "description": "The application dynamically reflects any Origin header supplied in the request and sets Access-Control-Allow-Credentials to true. This allows a malicious website to perform authenticated cross-origin reads of the user's private profile data."
}
```
