# Standards Reference: Deep Link Vulnerabilities

## OWASP Mobile Top 10 2024
| ID | Risk | Deep Link Relevance |
|----|------|-------------------|
| M4 | Insufficient Input/Output Validation | Injection via deep link parameters |
| M8 | Security Misconfiguration | Unverified App Links, missing scheme validation |

## OWASP MASVS v2.0 - MASVS-PLATFORM
| Control | Test |
|---------|------|
| MASVS-PLATFORM-1 | App validates deep link parameters before processing |
| MASVS-PLATFORM-2 | App does not expose sensitive functionality via URL schemes |

## CWE Mappings
| CWE | Title | Attack Vector |
|-----|-------|--------------|
| CWE-939 | Improper Authorization in Handler for Custom URL Scheme | Scheme hijacking |
| CWE-940 | Improper Verification of Source in URL Scheme Handler | Missing origin validation |
| CWE-79 | Cross-site Scripting | JavaScript injection via WebView deep links |
| CWE-601 | URL Redirection to Untrusted Site | Open redirect via URL parameter |
