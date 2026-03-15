# Standards Reference: Android Static Analysis with MobSF

## OWASP Mobile Top 10 2024 Mapping

| OWASP ID | Risk | MobSF Coverage |
|----------|------|----------------|
| M1 | Improper Credential Usage | Detects hardcoded API keys, passwords, tokens in source code and resources |
| M2 | Inadequate Supply Chain Security | Identifies third-party library versions with known CVEs |
| M5 | Insecure Communication | Flags missing certificate pinning, cleartext traffic, weak TLS |
| M7 | Insufficient Binary Protections | Checks ProGuard/R8 obfuscation, native binary protections |
| M8 | Security Misconfiguration | Analyzes AndroidManifest.xml for exported components, debug flags, backup settings |
| M9 | Insecure Data Storage | Detects SharedPreferences misuse, world-readable files, SQLite without encryption |
| M10 | Insufficient Cryptography | Identifies ECB mode, static IV, hardcoded encryption keys, weak algorithms |

## OWASP MASVS v2.0 Control Mapping

| MASVS Category | Controls | MobSF Static Checks |
|----------------|----------|---------------------|
| MASVS-STORAGE | Sensitive data storage | SharedPreferences analysis, file permission checks, database encryption |
| MASVS-CRYPTO | Cryptographic implementations | Algorithm strength, key management, IV randomness |
| MASVS-AUTH | Authentication mechanisms | Credential storage, biometric implementation review |
| MASVS-NETWORK | Network security | Network security config, certificate pinning, cleartext detection |
| MASVS-PLATFORM | Platform interaction | Intent filter analysis, content provider security, WebView configuration |
| MASVS-CODE | Code quality | Code obfuscation, debug symbols, error handling |
| MASVS-RESILIENCE | Reverse engineering resistance | Root detection, tamper detection, debugger detection |

## NIST SP 800-163 Rev 1: Vetting the Security of Mobile Applications

- Section 4.1: Static analysis as mandatory step in mobile app vetting process
- Section 4.2: Automated tools should check for known vulnerability patterns
- Section 5: Integration of vetting into enterprise mobile device management

## CWE Mappings for Common MobSF Findings

| CWE ID | Title | MobSF Finding Category |
|--------|-------|----------------------|
| CWE-312 | Cleartext Storage of Sensitive Information | Hardcoded credentials in source |
| CWE-319 | Cleartext Transmission of Sensitive Information | Missing HTTPS enforcement |
| CWE-327 | Use of Broken Cryptographic Algorithm | Weak crypto detection |
| CWE-330 | Use of Insufficiently Random Values | Static IV, predictable random |
| CWE-532 | Insertion of Sensitive Information into Log File | Logging sensitive data |
| CWE-749 | Exposed Dangerous Method or Function | Exported components without guards |
| CWE-919 | Weaknesses in Mobile Applications | General mobile-specific checks |
| CWE-925 | Improper Verification of Intent by Broadcast Receiver | Unprotected broadcast receivers |
