# Standards Reference: Mobile API Authentication Testing

## OWASP Mobile Top 10 2024

| OWASP ID | Risk | Testing Focus |
|----------|------|---------------|
| M1 | Improper Credential Usage | Hardcoded API keys, credential transmission |
| M3 | Insecure Authentication/Authorization | Auth bypass, IDOR, privilege escalation |

## OWASP API Security Top 10 2023

| API Risk | Test Case |
|----------|-----------|
| API1: Broken Object Level Authorization | Modify object IDs, test cross-user access |
| API2: Broken Authentication | JWT vulnerabilities, token replay, session management |
| API3: Broken Object Property Level Auth | Mass assignment, property-level access |
| API5: Broken Function Level Authorization | Admin endpoint access with user tokens |

## OWASP MASVS v2.0 - MASVS-AUTH

| Control | Test Method |
|---------|-------------|
| MASVS-AUTH-1 | Verify authentication enforcement on all sensitive endpoints |
| MASVS-AUTH-2 | Test token generation, validation, and revocation |
| MASVS-AUTH-3 | Assess multi-factor authentication implementation |

## CWE Mappings

| CWE | Title | Test |
|-----|-------|------|
| CWE-287 | Improper Authentication | Missing auth on endpoints |
| CWE-639 | Authorization Bypass Through User-Controlled Key | IDOR testing |
| CWE-798 | Hardcoded Credentials | API key in APK/IPA |
| CWE-613 | Insufficient Session Expiration | Token lifetime testing |
| CWE-384 | Session Fixation | Pre-auth token reuse |
