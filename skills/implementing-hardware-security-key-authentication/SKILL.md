---
name: implementing-hardware-security-key-authentication
description: 'Implements FIDO2/WebAuthn hardware security key authentication including
  registration ceremonies, authentication flows, YubiKey enrollment, and passkey migration
  strategies. Builds a complete relying party server using the python-fido2 library
  that supports cross-platform authenticators, resident key (discoverable credential)
  workflows, and user verification policies. Activates for requests involving FIDO2
  implementation, WebAuthn registration, hardware security key enrollment, YubiKey
  integration, or passkey migration from password-based authentication.

  '
domain: cybersecurity
subdomain: identity-and-access-management
tags:
- FIDO2
- WebAuthn
- hardware-security-key
- YubiKey
- passkeys
- passwordless-authentication
- CTAP2
version: 1.0.0
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0051
- AML.T0054
- AML.T0056
nist_ai_rmf:
- MEASURE-2.7
- MEASURE-2.5
- GOVERN-6.1
- MAP-5.1
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
---
# Implementing Hardware Security Key Authentication

## When to Use

- Deploying phishing-resistant multi-factor authentication (MFA) using FIDO2 hardware security keys for high-value accounts (administrators, developers, privileged users)
- Building a WebAuthn relying party server that supports both roaming authenticators (USB/NFC security keys) and platform authenticators (Windows Hello, Touch ID, Android biometrics)
- Migrating an existing password-based authentication system to support passkeys (discoverable credentials) as a primary or secondary authentication factor
- Enrolling YubiKey devices for an organization's workforce, including PIN setup, credential registration, and backup key provisioning
- Implementing passwordless authentication flows that comply with NIST SP 800-63B AAL3 (authenticator assurance level 3) requirements

**Do not use** without HTTPS in production (WebAuthn requires a secure origin), for systems where users cannot physically access a USB/NFC port, or as the sole authentication factor without a recovery mechanism for lost keys.

## Prerequisites

- Python 3.10+ with `fido2` (python-fido2 >= 2.0.0), `flask`, and `cryptography` libraries installed
- HTTPS-enabled web server (WebAuthn API requires secure context; localhost is exempt for development)
- FIDO2-compatible hardware security key (YubiKey 5 Series, SoloKeys, Titan Security Key) or platform authenticator
- Modern web browser supporting the WebAuthn API (Chrome 67+, Firefox 60+, Safari 14+, Edge 79+)
- Understanding of public key cryptography, challenge-response protocols, and HTTP session management

## Workflow

### Step 1: Relying Party Server Configuration

Configure the WebAuthn relying party (RP) identity and server:

- **Define RP identity**: Create a `PublicKeyCredentialRpEntity` with the relying party name (display name shown to users) and RP ID (the effective domain of the application). The RP ID must be a registrable domain suffix of the origin -- for example, `example.com` is valid for `https://auth.example.com` but `other.com` is not.
- **Initialize Fido2Server**: Instantiate the `Fido2Server` class from the python-fido2 library with the RP entity. The server handles challenge generation, attestation verification, and assertion validation.
- **Configure attestation preference**: Set the attestation conveyance preference to control whether the server requests proof of the authenticator's identity:
  - `none`: No attestation requested (simplest, recommended for most deployments)
  - `indirect`: Attestation may be provided but CA may anonymize it
  - `direct`: Full attestation chain from the authenticator's manufacturer
  - `enterprise`: Device-identifying attestation for managed environments
- **Session management**: Configure server-side sessions to store WebAuthn state between the begin and complete phases of registration/authentication ceremonies. Use secure, httponly cookies with SameSite=Strict.
- **Credential storage**: Design the database schema to store credential records: `credential_id` (binary), `public_key` (COSE key), `sign_count` (uint32 for clone detection), `user_id`, `created_at`, `last_used`, `display_name`, and `transports` (USB, NFC, BLE, internal).

### Step 2: Registration Ceremony (Credential Creation)

Implement the WebAuthn registration flow to create new credentials:

- **Begin registration**: Call `server.register_begin()` with the user entity (`PublicKeyCredentialUserEntity` containing user ID, username, and display name), the list of existing credentials for the user (to prevent duplicate registration), and options for `user_verification` and `authenticator_attachment`.
- **Authenticator selection criteria**:
  - `authenticator_attachment: cross-platform` restricts to roaming authenticators (USB/NFC keys)
  - `authenticator_attachment: platform` restricts to built-in authenticators (Touch ID, Windows Hello)
  - Omitting this field allows both types
  - `resident_key: required` forces creation of a discoverable credential (passkey) stored on the authenticator
  - `user_verification: required` enforces PIN or biometric verification on the authenticator
- **Client-side ceremony**: The browser calls `navigator.credentials.create()` with the options from the server. The authenticator generates a new key pair, stores the private key in its secure element, and returns the public key, credential ID, attestation object, and client data JSON.
- **Complete registration**: Call `server.register_complete()` with the saved state and the client response. The server verifies the attestation signature, extracts the credential public key and ID, and returns `AuthenticatorData` containing the credential data to store.
- **Store credential**: Persist the `credential_data` (contains `credential_id`, `public_key` as COSE key, and `sign_count`) to the database associated with the user account.

### Step 3: Authentication Ceremony (Assertion)

Implement the WebAuthn authentication flow to verify credentials:

- **Begin authentication**: Call `server.authenticate_begin()` with the list of registered credentials for the user (or omit for discoverable credential flows where the authenticator identifies the user). Set `user_verification` based on the assurance level required.
- **Client-side assertion**: The browser calls `navigator.credentials.get()` with the server options. The authenticator locates the matching credential, performs user verification if required, increments the signature counter, and signs the challenge with the private key.
- **Complete authentication**: Call `server.authenticate_complete()` with the saved state, registered credentials, and the client response. The server verifies the assertion signature against the stored public key and validates the signature counter has incremented (clone detection).
- **Update sign count**: After successful authentication, update the stored `sign_count` for the credential. If the new sign count is not greater than the stored value, the key may have been cloned -- flag this as a security event.
- **Discoverable credential flow**: For passwordless authentication, the user does not need to enter a username first. The authenticator presents all discoverable credentials for the RP ID, and the selected credential's `userHandle` identifies the user.

### Step 4: YubiKey Enrollment and Management

Implement organizational YubiKey provisioning workflows:

- **PIN initialization**: Before first use, a YubiKey requires a FIDO2 PIN (minimum 4 characters, 8 retries before lockout). Guide users through PIN setup using the Yubico Authenticator application or programmatically via the CTAP2 `clientPin` command.
- **Primary key enrollment**: Register the user's primary YubiKey with their account. Store the credential with a user-friendly label (e.g., "USB-A YubiKey - Office") and the authenticator's AAGUID for device identification.
- **Backup key enrollment**: Require users to register at least two security keys. The backup key should be stored separately (home, safety deposit box). Both keys must be registered to the same account so either can authenticate.
- **Key attestation verification**: For enterprise deployments, verify the attestation certificate chain to confirm the key is a genuine YubiKey from Yubico. Compare the AAGUID against Yubico's published values to identify the exact model.
- **Key lifecycle management**: Implement administrative functions to list a user's registered keys, revoke compromised keys, force re-enrollment, and audit key usage patterns (last authentication time, total authentications).

### Step 5: Passkey Migration Strategy

Plan and execute migration from passwords to passkeys:

- **Phased rollout**: Begin with voluntary passkey enrollment alongside existing password authentication. Track adoption metrics (percentage of users with passkeys, percentage of logins using passkeys vs. passwords).
- **Credential upgrade flow**: When a user authenticates with a password, prompt them to register a passkey. Present the WebAuthn registration dialog immediately after successful password login to minimize friction.
- **Cross-device passkeys**: Support synced passkeys (passkeys stored in platform credential managers like iCloud Keychain, Google Password Manager, or 1Password) for users who do not have hardware security keys. These provide phishing resistance without requiring dedicated hardware.
- **Account recovery**: Design recovery flows for users who lose all their security keys:
  - Recovery codes generated at enrollment time (printed, stored in password manager)
  - Supervised re-enrollment by an administrator after identity verification
  - Temporary time-limited password login with mandatory key re-enrollment
  - Never allow recovery via email or SMS alone, as these defeat the phishing resistance
- **Password deprecation timeline**: After passkey adoption exceeds the target threshold, enforce passkey-only authentication for high-privilege accounts first, then expand to all accounts. Maintain password as a fallback during the transition window.
- **Monitoring and metrics**: Track registration success rates, authentication failure rates (wrong key, timeout, cancelled), mean time to authenticate, and the ratio of passkey to password logins.

## Key Concepts

| Term | Definition |
|------|------------|
| **FIDO2** | An umbrella term for the combination of the W3C WebAuthn API and the FIDO Alliance CTAP2 protocol, enabling passwordless and phishing-resistant authentication using public key cryptography |
| **WebAuthn** | The W3C Web Authentication API that allows web applications to create and use public key credentials via `navigator.credentials.create()` (registration) and `navigator.credentials.get()` (authentication) |
| **CTAP2** | Client to Authenticator Protocol version 2; the protocol used by the browser (client) to communicate with external authenticators over USB, NFC, or BLE |
| **Relying Party (RP)** | The web application or service that requests authentication; identified by its RP ID (a domain) and RP name (display string) |
| **Discoverable Credential (Passkey)** | A credential stored on the authenticator that can be enumerated without the RP providing a credential ID, enabling username-less authentication flows |
| **Attestation** | Cryptographic proof from the authenticator about its identity and properties; used by the RP to verify the authenticator model and manufacturer |
| **AAGUID** | Authenticator Attestation Globally Unique Identifier; a 128-bit value identifying the authenticator model (e.g., all YubiKey 5 NFC devices share the same AAGUID) |
| **Sign Count** | A monotonically increasing counter maintained by the authenticator and included in each assertion; used by the RP to detect cloned authenticators |
| **User Verification (UV)** | Local authentication on the authenticator itself (PIN, fingerprint, face recognition) that proves the person holding the authenticator is the legitimate owner |

## Tools & Systems

- **python-fido2**: Yubico's official Python library (v2.0+) providing `Fido2Server` for relying party implementation and `CtapHidDevice`/`Fido2Client` for direct authenticator communication over USB
- **YubiKey 5 Series**: Yubico hardware security keys supporting FIDO2/CTAP2, U2F, PIV, OpenPGP, and OTP; available in USB-A, USB-C, NFC, and Nano form factors
- **py_webauthn**: Duo Labs' Python WebAuthn library providing `generate_registration_options()`, `verify_registration_response()`, `generate_authentication_options()`, and `verify_authentication_response()` functions
- **Yubico Authenticator**: Desktop and mobile application for managing YubiKey FIDO2 credentials, setting PINs, and viewing registered accounts
- **WebAuthn.io / demo.yubico.com**: Online testing tools for verifying WebAuthn registration and authentication flows against real authenticators

## Common Scenarios

### Scenario: Deploying FIDO2 MFA for a Development Team

**Context**: A software company wants to replace TOTP-based MFA with hardware security keys for its 50-person development team. Developers have root access to production infrastructure and are high-value targets for phishing attacks. The company has standardized on YubiKey 5 NFC.

**Approach**:
1. Provision YubiKey 5 NFC keys (2 per developer: primary + backup) and distribute in tamper-evident packaging with initial PIN setup instructions
2. Deploy the WebAuthn relying party server integrated with the company's SSO (OAuth 2.0 / OpenID Connect) provider, configured with `authenticator_attachment: cross-platform` and `user_verification: required`
3. Run enrollment sessions where each developer registers both keys to their account, with attestation verification confirming genuine YubiKey 5 NFC AAGUIDs
4. Configure the SSO provider to require FIDO2 as the second factor for all developer accounts, with a 30-day grace period where TOTP remains available
5. Implement a self-service portal for key management: view registered keys, register replacement keys, and report lost/stolen keys (which triggers immediate credential revocation and re-enrollment)
6. After the grace period, disable TOTP for developer accounts. Monitor authentication logs for any fallback attempts and provide 1:1 support for remaining holdouts
7. Achieve 100% FIDO2 adoption for the development team, reducing phishing risk to near-zero for production infrastructure access

**Pitfalls**:
- Not requiring backup key enrollment, leading to account lockouts when a single key is lost
- Setting `user_verification: discouraged` which allows anyone who physically possesses the key to authenticate without a PIN
- Forgetting to validate the sign counter, missing cloned key attacks
- Not supporting NFC for developers who primarily work from tablets or phones
- Allowing TOTP as a permanent fallback, which undermines the phishing resistance of the FIDO2 deployment

### Scenario: Implementing Passwordless Login for a Customer-Facing Application

**Context**: An e-commerce platform wants to offer passkey-based passwordless login to its 2 million users as an alternative to passwords, reducing account takeover from credential stuffing and phishing.

**Approach**:
1. Implement WebAuthn with `resident_key: required` to create discoverable credentials that enable username-less login
2. Support both platform authenticators (Touch ID, Windows Hello, Android biometrics) and roaming authenticators (security keys) by omitting `authenticator_attachment`
3. Add a "Sign in with a passkey" button to the login page that triggers `navigator.credentials.get()` with an empty `allowCredentials` list, prompting the authenticator to present available passkeys
4. After successful passkey creation, prompt users to create a passkey on a second device for redundancy
5. Maintain password login as a fallback during the rollout period, with a persistent prompt encouraging passkey setup after each password login
6. Track metrics: passkey registration rate (target 30% in first quarter), passkey vs. password login ratio, authentication failure rates, and account takeover incidents
7. After 6 months, offer incentives (extended session duration, reduced CAPTCHA) for users who switch to passkey-only authentication

**Pitfalls**:
- Not handling the case where a user's platform authenticator (e.g., laptop Touch ID) is unavailable and they need cross-device authentication via QR code
- Assuming all users have biometric-capable devices; some will need to fall back to PIN-based verification
- Not implementing proper account recovery for users who lose access to all registered passkeys
- Ignoring browser compatibility gaps, particularly in older Safari versions on iOS

## Output Format

```
## FIDO2 Deployment Report

**Application**: auth.example.com
**RP ID**: example.com
**Date**: 2026-03-19

### Enrollment Summary
- **Total Users**: 50
- **Users with Primary Key**: 50 (100%)
- **Users with Backup Key**: 47 (94%)
- **Authenticator Models**: YubiKey 5 NFC (48), YubiKey 5C NFC (2)

### Authentication Metrics (Last 30 Days)
- **Total Authentications**: 12,847
- **FIDO2 Authentications**: 12,203 (95.0%)
- **TOTP Fallback**: 644 (5.0%) -- grace period active
- **Mean Authentication Time**: 2.3 seconds
- **Authentication Failures**: 127 (0.99%)
  - User cancelled: 89
  - Timeout: 23
  - Invalid signature: 12
  - Sign count regression (possible clone): 3

### Security Events
- **Lost Key Reports**: 2
  - User A: primary key lost 2026-03-12, revoked, backup promoted, new backup enrolled
  - User B: backup key damaged 2026-03-15, revoked, replacement enrolled

### Credential Details
| User | Key Label | AAGUID | Registered | Last Used | Sign Count |
|------|-----------|--------|------------|-----------|------------|
| alice | YubiKey Primary | 2fc0579f... | 2026-02-15 | 2026-03-19 | 847 |
| alice | YubiKey Backup | 2fc0579f... | 2026-02-15 | 2026-03-01 | 12 |
| bob | YubiKey Primary | 2fc0579f... | 2026-02-16 | 2026-03-19 | 631 |
```
