---
name: implementing-saml-sso-with-okta
description: Implement SAML 2.0 Single Sign-On (SSO) using Okta as the Identity Provider (IdP). This skill covers end-to-end configuration of SAML authentication flows, attribute mapping, certificate management, a
domain: cybersecurity
subdomain: identity-access-management
tags: [iam, identity, access-control, authentication, saml, sso, okta]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing SAML SSO with Okta

## Overview
Implement SAML 2.0 Single Sign-On (SSO) using Okta as the Identity Provider (IdP). This skill covers end-to-end configuration of SAML authentication flows, attribute mapping, certificate management, and security hardening for enterprise SSO deployments.

## Objectives
- Configure Okta as a SAML 2.0 Identity Provider
- Implement SP-initiated and IdP-initiated SSO flows
- Map SAML attributes and configure assertion encryption
- Enforce SHA-256 signatures and secure certificate rotation
- Test SSO flows with SAML tracer tools
- Implement Single Logout (SLO) handling

## Key Concepts

### SAML 2.0 Authentication Flow
1. **SP-Initiated Flow**: User accesses Service Provider -> SP generates AuthnRequest -> Redirect to Okta IdP -> User authenticates -> Okta sends SAML Response -> SP validates assertion -> Access granted
2. **IdP-Initiated Flow**: User authenticates at Okta -> Selects application -> Okta sends unsolicited SAML Response -> SP validates -> Access granted

### Critical Security Requirements
- **SHA-256 Signatures**: All SAML assertions must use SHA-256 (not SHA-1) for digital signatures
- **Assertion Encryption**: Encrypt SAML assertions using AES-256 to protect attribute values in transit
- **Audience Restriction**: Configure audience URI to prevent assertion replay across different SPs
- **NotBefore/NotOnOrAfter**: Enforce time validity windows to prevent stale assertion usage
- **InResponseTo Validation**: Verify assertion corresponds to the original AuthnRequest

### Okta Application Configuration
- **Single Sign-On URL**: The ACS (Assertion Consumer Service) endpoint on the SP
- **Audience URI (SP Entity ID)**: Unique identifier for the SP
- **Name ID Format**: EmailAddress, Persistent, or Transient
- **Attribute Statements**: Map Okta user profile attributes to SAML assertion attributes
- **Group Attribute Statements**: Include group membership for RBAC

## Implementation Steps

### Step 1: Create SAML Application in Okta
1. Navigate to Applications > Create App Integration
2. Select SAML 2.0 as the sign-on method
3. Configure General Settings (App Name, Logo)
4. Set Single Sign-On URL (ACS URL)
5. Set Audience URI (SP Entity ID)
6. Configure Name ID Format and Application Username

### Step 2: Configure Attribute Mapping
- Map `user.email` to `email` attribute
- Map `user.firstName` and `user.lastName` to name attributes
- Add group attribute statements for role-based access
- Configure attribute value formats (Basic, URI Reference, Unspecified)

### Step 3: Download and Install IdP Metadata
- Download Okta IdP metadata XML
- Extract IdP SSO URL, IdP Entity ID, and X.509 certificate
- Install certificate on SP side for signature validation
- Configure SP metadata with ACS URL and Entity ID

### Step 4: Implement SP-Side SAML Processing
- Parse and validate SAML Response XML
- Verify digital signature using IdP certificate
- Check audience restriction, time conditions, and InResponseTo
- Extract authenticated user identity and attributes
- Create application session based on assertion data

### Step 5: Security Hardening
- Enforce SHA-256 for all signature operations
- Enable assertion encryption with AES-256-CBC
- Configure session timeout and re-authentication policies
- Implement SAML artifact binding for sensitive deployments
- Set up certificate rotation procedure before expiry

### Step 6: Testing and Validation
- Use SAML Tracer browser extension for debugging
- Validate SP-initiated and IdP-initiated flows
- Test with multiple user accounts and group memberships
- Verify SLO functionality
- Test certificate rotation without downtime

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Authentication | IA-2 | Multi-factor authentication through Okta |
| Session Management | SC-23 | SAML session lifetime controls |
| Audit Logging | AU-3 | Log all SSO authentication events |
| Certificate Management | SC-17 | PKI certificate lifecycle management |
| Access Enforcement | AC-3 | SAML attribute-based access control |

## Common Pitfalls
- Using SHA-1 instead of SHA-256 for SAML signatures
- Not validating InResponseTo in SAML responses (replay attacks)
- Clock skew between IdP and SP causing assertion rejection
- Failing to restrict audience URI allowing assertion forwarding
- Not implementing certificate rotation before expiry causes outage

## Verification
- [ ] SAML SSO login completes successfully via SP-initiated flow
- [ ] IdP-initiated flow correctly authenticates users
- [ ] SAML assertions use SHA-256 signatures
- [ ] Attribute mapping correctly populates user profile
- [ ] Session timeout forces re-authentication
- [ ] SLO properly terminates sessions on both IdP and SP
- [ ] Certificate rotation tested without service interruption
