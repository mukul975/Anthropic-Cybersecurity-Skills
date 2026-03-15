# Standards Reference: Insecure Data Storage in Mobile

## OWASP Mobile Top 10 2024 Mapping

| OWASP ID | Risk | Data Storage Relevance |
|----------|------|----------------------|
| M1 | Improper Credential Usage | Hardcoded credentials in SharedPreferences, plists, databases |
| M6 | Inadequate Privacy Controls | PII stored unencrypted, accessible via backup extraction |
| M8 | Security Misconfiguration | allowBackup=true, world-readable files, missing encryption |
| M9 | Insecure Data Storage | Primary focus: all local storage vulnerabilities |
| M10 | Insufficient Cryptography | Weak encryption of local databases, hardcoded keys |

## OWASP MASVS v2.0 - MASVS-STORAGE Controls

| Control | Description | Test Method |
|---------|-------------|-------------|
| MASVS-STORAGE-1 | App securely stores sensitive data | Inspect SharedPreferences, keychain, databases |
| MASVS-STORAGE-2 | App prevents sensitive data leakage | Check logs, clipboard, backups, screenshots |

## NIST SP 800-163 Rev 1 - Mobile App Vetting

- Section 4.3.1: Data storage analysis for sensitive information at rest
- Section 4.3.2: Verification of encryption implementation for stored data
- Section 5.2: Data protection requirements for enterprise mobile apps

## CWE Mappings

| CWE ID | Title | Storage Type |
|--------|-------|-------------|
| CWE-312 | Cleartext Storage of Sensitive Information | SharedPreferences, plists, SQLite |
| CWE-316 | Cleartext Storage in Memory | Process memory, clipboard |
| CWE-359 | Exposure of Private Personal Information | PII in unencrypted databases |
| CWE-522 | Insufficiently Protected Credentials | Passwords in SharedPreferences |
| CWE-532 | Information Exposure Through Log Files | Sensitive data in logcat/syslog |
| CWE-921 | Storage of Sensitive Data in Unprotected Mechanism | External storage, world-readable |
| CWE-922 | Insecure Storage of Sensitive Information | General insecure storage |

## Android Keystore Best Practices

| Practice | Secure | Insecure |
|----------|--------|----------|
| Key storage | Android Keystore (hardware-backed) | Hardcoded in APK or SharedPreferences |
| Database encryption | SQLCipher with Keystore-derived key | Unencrypted SQLite |
| Shared Preferences | EncryptedSharedPreferences (Jetpack) | MODE_PRIVATE without encryption |
| File encryption | AES-256-GCM with Keystore key | Plaintext files in internal storage |

## iOS Data Protection Classes

| Class | When Accessible | Use Case |
|-------|----------------|----------|
| NSFileProtectionComplete | Only when unlocked | Highly sensitive data |
| NSFileProtectionCompleteUnlessOpen | While open/unlocked | Files written in background |
| NSFileProtectionCompleteUntilFirstUserAuthentication | After first unlock | Background-accessible data |
| NSFileProtectionNone | Always | Non-sensitive cached data |
