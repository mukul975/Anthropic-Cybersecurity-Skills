# Standards Reference: Mobile Traffic Interception with Burp Suite

## OWASP Mobile Top 10 2024 Mapping

| OWASP ID | Risk | Burp Suite Testing Coverage |
|----------|------|----------------------------|
| M1 | Improper Credential Usage | Identify credentials in plaintext, weak token formats in API traffic |
| M3 | Insecure Authentication/Authorization | Test auth bypass, session management, IDOR via request manipulation |
| M4 | Insufficient Input/Output Validation | SQL injection, XSS, command injection via Burp Scanner/Repeater |
| M5 | Insecure Communication | Detect cleartext HTTP, weak TLS, missing HSTS, certificate validation |
| M8 | Security Misconfiguration | Identify verbose error messages, debug endpoints, missing security headers |

## OWASP MASVS v2.0 Control Mapping

| MASVS Category | Burp Suite Assessment | Test Method |
|----------------|----------------------|-------------|
| MASVS-NETWORK | TLS configuration, certificate pinning, cleartext detection | Proxy interception, SSL scan |
| MASVS-AUTH | Token validation, session handling, credential transmission | Repeater manipulation |
| MASVS-STORAGE | Sensitive data in API responses cached client-side | Response header analysis |
| MASVS-PLATFORM | Deep link parameter injection, WebView URL loading | Request crafting |

## OWASP API Security Top 10 2023

| API Risk | Burp Suite Test |
|----------|----------------|
| API1: Broken Object Level Authorization | Modify object IDs in intercepted requests |
| API2: Broken Authentication | Replay tokens, test token expiration |
| API3: Broken Object Property Level Auth | Modify response/request properties |
| API5: Broken Function Level Authorization | Access admin endpoints with user tokens |
| API8: Security Misconfiguration | Check response headers, error handling |

## CWE Mappings

| CWE ID | Title | Detection Method |
|--------|-------|-----------------|
| CWE-200 | Exposure of Sensitive Information | Inspect API responses for data leakage |
| CWE-295 | Improper Certificate Validation | Test with self-signed proxy certificate |
| CWE-319 | Cleartext Transmission | Monitor for HTTP (non-HTTPS) requests |
| CWE-352 | Cross-Site Request Forgery | Check for anti-CSRF tokens in requests |
| CWE-613 | Insufficient Session Expiration | Test token validity after logout |
