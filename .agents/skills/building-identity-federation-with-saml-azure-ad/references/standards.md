# Identity Federation with SAML Azure AD - Standards Reference

## Federation Protocols

### SAML 2.0 (OASIS)
- Security Assertion Markup Language version 2.0
- XML-based framework for exchanging authentication/authorization data
- Profiles: Web Browser SSO, Enhanced Client or Proxy, Single Logout
- Bindings: HTTP Redirect, HTTP POST, HTTP Artifact, SOAP

### WS-Federation (OASIS)
- Web Services Federation Language
- Used by AD FS for passive federation (browser-based)
- Token types: SAML 1.1, SAML 2.0

### OpenID Connect
- Built on OAuth 2.0
- JSON/REST-based (vs. SAML XML)
- Used by Azure AD as primary protocol for modern applications
- JWT tokens instead of SAML assertions

## Microsoft Entra ID Federation Requirements

### Supported Federation Protocols
| Protocol | Use Case | Token Format |
|----------|----------|-------------|
| SAML 2.0 | Enterprise SSO, third-party apps | SAML assertion (XML) |
| WS-Federation | Legacy applications, AD FS | SAML token |
| OpenID Connect | Modern web/mobile apps | JWT |

### Domain Federation Requirements
- Domain must be verified in Azure AD
- Only one federation configuration per domain
- Password hash sync recommended as backup
- Azure AD Connect for hybrid identity sync

## Compliance Mapping

### NIST SP 800-63C - Federation and Assertions
- FAL1: Bearer assertion, direct presentation
- FAL2: Bearer assertion with additional security
- FAL3: Holder-of-key assertion

### FedRAMP
- IA-2: Identification and Authentication
- IA-5: Authenticator Management
- IA-8: Identification and Authentication (Non-Organizational Users)
- Federation required for cross-organization access

### ISO 27001:2022
- A.5.16: Identity management
- A.5.17: Authentication information
- A.8.5: Secure authentication
