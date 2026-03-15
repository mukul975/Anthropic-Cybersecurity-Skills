# Standards and References - SAML SSO with Okta

## SAML 2.0 Standards
- **OASIS SAML 2.0 Core**: Defines assertions, protocols, bindings, and profiles
  - http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
- **SAML 2.0 Bindings**: HTTP Redirect, HTTP POST, HTTP Artifact, SOAP
  - http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
- **SAML 2.0 Profiles**: Web Browser SSO Profile, Single Logout Profile
  - http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf

## NIST Standards
- **NIST SP 800-63B**: Digital Identity Guidelines - Authentication and Lifecycle Management
  - https://pages.nist.gov/800-63-3/sp800-63b.html
- **NIST SP 800-53 Rev 5**: Security and Privacy Controls
  - IA-2: Identification and Authentication (Organizational Users)
  - IA-8: Identification and Authentication (Non-Organizational Users)
  - AC-3: Access Enforcement
  - AU-3: Content of Audit Records
  - SC-23: Session Authenticity
- **NIST SP 1800-35**: Implementing a Zero Trust Architecture
  - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-35.pdf

## Okta Documentation
- **Okta SAML Integration Guide**: https://developer.okta.com/docs/guides/build-sso-integration/saml2/main/
- **Understanding SAML with Okta**: https://developer.okta.com/docs/concepts/saml/
- **Okta SAML App Configuration**: https://help.okta.com/en-us/content/topics/apps/apps-about-saml.htm

## Security Best Practices
- **OWASP SAML Security Cheat Sheet**: Covers SAML signature wrapping attacks, XML injection
- **SSO Best Practices 2025**: SHA-256 enforcement, assertion encryption, certificate rotation
  - https://clerk.com/articles/sso-best-practices-for-secure-scalable-logins

## XML Security Standards
- **XML Signature (XMLDSig)**: W3C standard for XML digital signatures
- **XML Encryption**: W3C standard for encrypting XML content
- **XML Canonicalization (C14N)**: Required for consistent signature verification

## Compliance Frameworks
- **SOC 2 Type II**: Logical access controls through SSO
- **ISO 27001**: A.9.4.2 Secure log-on procedures
- **PCI DSS 4.0**: Requirement 8 - Identify Users and Authenticate Access
