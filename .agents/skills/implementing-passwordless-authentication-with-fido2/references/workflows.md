# FIDO2 Passwordless Authentication Workflows

## Workflow 1: Security Key Enrollment
1. User receives FIDO2 security key (YubiKey, Titan Key)
2. User navigates to enrollment portal
3. System generates WebAuthn registration challenge
4. Browser prompts user to insert/tap security key
5. User verifies with PIN or biometric on key
6. Key generates unique public/private key pair
7. Public key registered with relying party
8. User tests authentication with enrolled key

## Workflow 2: Passkey Authentication Flow
1. User visits login page, enters username
2. Server sends WebAuthn authentication challenge
3. Browser prompts for authenticator (key, biometric, passkey)
4. User verifies identity (touch key, scan fingerprint, enter PIN)
5. Authenticator signs challenge with private key
6. Server validates signature with stored public key
7. User authenticated, session created

## Workflow 3: Migration from Passwords to Passwordless
1. Phase 1: Deploy FIDO2 to pilot group (IT, security teams)
2. Phase 2: Enable coexistence (password + FIDO2)
3. Phase 3: Expand FIDO2 enrollment to all users
4. Phase 4: Set FIDO2-only policy per group
5. Phase 5: Disable password authentication for migrated groups
6. Phase 6: Monitor for fallback authentication attempts

## Workflow 4: Lost/Stolen Key Recovery
1. User reports lost security key
2. Admin disables lost key in identity provider
3. User authenticates via backup method (recovery codes, backup key)
4. User enrolls replacement security key
5. Old key permanently revoked
6. Security team reviews for unauthorized usage of lost key
