# Standards Reference: iOS App Security with Objection

## OWASP Mobile Top 10 2024 Mapping

| OWASP ID | Risk | Objection Testing Coverage |
|----------|------|---------------------------|
| M1 | Improper Credential Usage | Keychain dumping, memory string search for hardcoded credentials |
| M3 | Insecure Authentication/Authorization | Hook authentication methods, bypass biometric checks |
| M5 | Insecure Communication | SSL pinning bypass, network class hooking |
| M7 | Insufficient Binary Protections | Jailbreak detection bypass, Frida detection assessment |
| M8 | Security Misconfiguration | Info.plist review, URL scheme analysis, ATS configuration |
| M9 | Insecure Data Storage | NSUserDefaults inspection, SQLite database access, file system review |

## OWASP MASVS v2.0 Control Mapping

| MASVS Category | Objection Commands | Assessment Area |
|----------------|-------------------|-----------------|
| MASVS-STORAGE | `ios keychain dump`, `ios nsuserdefaults get`, `sqlite connect` | Sensitive data in keychain, NSUserDefaults, databases |
| MASVS-CRYPTO | `memory search`, hook crypto framework calls | Key storage, algorithm selection |
| MASVS-AUTH | Hook LAContext, authentication classes | Biometric bypass, session management |
| MASVS-NETWORK | `ios sslpinning disable`, hook NSURLSession | Certificate pinning, cleartext traffic |
| MASVS-PLATFORM | Hook URL scheme handlers, pasteboard monitor | Deep link security, clipboard exposure |
| MASVS-CODE | `memory list modules`, binary inspection | Debugging symbols, framework analysis |
| MASVS-RESILIENCE | `ios jailbreak disable`, Frida detection hooks | Anti-tampering, anti-debugging |

## OWASP MASTG Test Cases

| Test ID | Description | Objection Approach |
|---------|-------------|-------------------|
| MASTG-TEST-0053 | Testing Local Storage for Sensitive Data | `ios keychain dump`, filesystem inspection |
| MASTG-TEST-0057 | Testing Backups for Sensitive Data | Check backup exclusion attributes |
| MASTG-TEST-0060 | Testing Custom URL Schemes | Hook `application:openURL:options:` |
| MASTG-TEST-0063 | Testing for Sensitive Data in Logs | Monitor NSLog calls via hooking |
| MASTG-TEST-0066 | Testing Enforced App Transport Security | Inspect Info.plist ATS configuration |

## Apple Platform Security Requirements

| Requirement | Assessment Method |
|-------------|-------------------|
| Keychain Access Control | Verify kSecAttrAccessible values via keychain dump |
| App Transport Security | Check Info.plist for NSAllowsArbitraryLoads exceptions |
| Data Protection API | Verify file protection attributes on sensitive files |
| Secure Enclave Usage | Hook SecKey operations for biometric-protected keys |
