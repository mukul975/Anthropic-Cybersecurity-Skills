# API Reference: Implementing Passwordless Authentication with FIDO2

## WebAuthn Registration Flow

```javascript
// 1. Server generates challenge
const options = await navigator.credentials.create({
  publicKey: {
    challenge: new Uint8Array(32),
    rp: { name: "Example Corp", id: "example.com" },
    user: { id: userId, name: "user@example.com", displayName: "User" },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },   // ES256
      { type: "public-key", alg: -257 }, // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",  // or "cross-platform"
      residentKey: "required",              // for passkeys
      userVerification: "required",
    },
    attestation: "direct",
  }
});
```

## WebAuthn Authentication Flow

```javascript
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: serverChallenge,
    rpId: "example.com",
    allowCredentials: [],  // empty for discoverable credentials (passkeys)
    userVerification: "required",
  }
});
```

## python-fido2 Server Library

```python
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

rp = PublicKeyCredentialRpEntity(id="example.com", name="Example")
server = Fido2Server(rp)

# Registration
registration_data, state = server.register_begin(user, credentials)
auth_data = server.register_complete(state, response)

# Authentication
request_data, state = server.authenticate_begin(credentials)
server.authenticate_complete(state, credentials, credential_id, client_data, auth_data, signature)
```

## FIDO2 Authenticator Types

| Type | Example | Attachment | Passkey Support |
|------|---------|------------|-----------------|
| Platform | Windows Hello, Touch ID | platform | Yes |
| Roaming | YubiKey, Titan Key | cross-platform | Yes (FIDO2) |
| Software | 1Password, iCloud Keychain | platform | Yes |

## COSE Algorithm Identifiers

| COSE ID | Algorithm | Use |
|---------|-----------|-----|
| -7 | ES256 (P-256) | Preferred for FIDO2 |
| -257 | RS256 | Legacy compatibility |
| -8 | EdDSA (Ed25519) | Strong, compact |
| -35 | ES384 (P-384) | Higher security |

## NIST SP 800-63B AAL Levels

| Level | Requirements | FIDO2 Mapping |
|-------|-------------|---------------|
| AAL1 | Single factor | Not applicable |
| AAL2 | Two factors | FIDO2 + PIN/biometric |
| AAL3 | Hardware crypto + verifier impersonation resistance | FIDO2 hardware key |

## Azure AD FIDO2 Configuration

```powershell
# Enable FIDO2 in Azure AD
Set-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
  -AuthenticationMethodConfigurationId "fido2" `
  -State "enabled" `
  -AdditionalProperties @{
    isSelfServiceRegistrationAllowed = $true
    isAttestationEnforced = $true
  }
```

### References

- WebAuthn Spec: https://www.w3.org/TR/webauthn-3/
- FIDO Alliance: https://fidoalliance.org/specifications/
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
- python-fido2: https://github.com/Yubico/python-fido2
