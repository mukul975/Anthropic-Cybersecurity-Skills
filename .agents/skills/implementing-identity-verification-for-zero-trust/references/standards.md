# Standards and Frameworks Reference

## NIST SP 800-207: Zero Trust Architecture - Identity

### Core Identity Tenets
- All resource authentication and authorization are dynamic and strictly enforced before access is allowed
- The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture
- Access decisions should consider behavioral attributes, environmental attributes, and the identity of the requester

### Policy Engine Identity Inputs
The Policy Engine (PE) uses the following identity-related inputs:
- User identity and attributes from the IdP
- Device identity and posture from the endpoint management system
- Behavioral attributes from user and entity behavior analytics (UEBA)
- Environmental attributes (location, time, network)

## NIST SP 800-63B: Digital Identity Guidelines

### Authentication Assurance Levels (AAL)
| AAL | Description | Methods | Zero Trust Mapping |
|---|---|---|---|
| AAL1 | Some assurance | Single-factor (password) | Insufficient for ZT |
| AAL2 | High confidence | Multi-factor (push notification, OTP) | Minimum for ZT |
| AAL3 | Very high confidence | Hardware-based (FIDO2, PIV card) | Target for ZT |

### Phishing-Resistant Authenticators
- FIDO2/WebAuthn: Cryptographic authentication bound to origin domain
- PIV/CAC smart cards: Certificate-based authentication
- Not phishing-resistant: SMS OTP, voice calls, push notifications, TOTP

## CISA Zero Trust Maturity Model v2.0 - Identity Pillar

| Maturity Level | Authentication | Identity Store | Risk Assessment | Visibility |
|---|---|---|---|---|
| Traditional | Password + basic MFA | Multiple disconnected stores | None | Basic audit logs |
| Initial | MFA for all users | Federated IdP | Static risk rules | Centralized auth logs |
| Advanced | Phishing-resistant MFA | Single authoritative IdP with SCIM | Risk-based conditional access | Identity analytics |
| Optimal | Continuous verification | Automated lifecycle governance | AI-driven threat detection | Real-time UEBA |

## FIDO Alliance Standards

### FIDO2 / WebAuthn
- W3C Web Authentication specification for passwordless authentication
- Public-key cryptography: private key never leaves the authenticator
- Origin-bound: authentication is cryptographically tied to the service domain
- Resistant to phishing, replay, and man-in-the-middle attacks

### Passkeys
- Evolution of FIDO2 for consumer and enterprise use
- Synced across devices via platform credential managers (iCloud Keychain, Google Password Manager)
- Discoverable credentials eliminate need to remember usernames

## Microsoft Entra (Azure AD) Identity Protection

### Risk Detection Categories
| Risk Type | Detection | Response |
|---|---|---|
| Anonymous IP | Sign-in from anonymous proxy/VPN | Require MFA |
| Atypical travel | Impossible travel between sign-in locations | Block + investigate |
| Malware-linked IP | Sign-in from known malicious IP | Block |
| Unfamiliar sign-in | Unusual sign-in properties | Step-up auth |
| Leaked credentials | Credentials found in dark web dumps | Force password reset |
| Token anomaly | Unusual token characteristics | Revoke session |

### Continuous Access Evaluation Protocol (CAEP)
- Real-time token revocation on security events
- Critical events: user disabled, password changed, high risk detected
- Reduces token lifetime gap from hours to near real-time
- Supported by Microsoft 365, Exchange Online, SharePoint Online

## Okta Identity Security

### Okta ThreatInsight
- Pre-authentication threat detection using IP reputation
- Credential stuffing protection
- Bot detection and rate limiting
- Anomalous location and device detection

### Okta FastPass
- Passwordless, phishing-resistant authentication
- Device-bound biometric verification
- Continuous device trust assessment
- No shared secrets transmitted over network
