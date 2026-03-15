# Standards Reference: iOS Reverse Engineering with Frida

## OWASP Mobile Top 10 2024 Mapping

| OWASP ID | Risk | RE Assessment |
|----------|------|---------------|
| M1 | Improper Credential Usage | Extract hardcoded keys via runtime hooking |
| M7 | Insufficient Binary Protections | Assess anti-RE measures (obfuscation, anti-debug, anti-Frida) |
| M10 | Insufficient Cryptography | Hook CommonCrypto to extract keys and observe algorithms |

## OWASP MASVS v2.0 - MASVS-RESILIENCE Controls

| Control | Description | Frida Test Method |
|---------|-------------|-------------------|
| MASVS-RESILIENCE-1 | App detects and responds to reverse engineering | Test with Frida attachment, observe detection |
| MASVS-RESILIENCE-2 | App detects tampering | Modify binary, observe integrity checks |
| MASVS-RESILIENCE-3 | App uses obfuscation | Assess class/method name readability |
| MASVS-RESILIENCE-4 | App detects debuggers | Attach debugger, check ptrace/sysctl hooks |

## CWE Mappings

| CWE ID | Title | RE Discovery Method |
|--------|-------|-------------------|
| CWE-798 | Use of Hard-coded Credentials | Hook string initialization, NSUserDefaults access |
| CWE-321 | Use of Hard-coded Cryptographic Key | Hook CCCrypt, SecKeyCreateWithData |
| CWE-327 | Broken Crypto Algorithm | Observe algorithm parameter in CCCrypt calls |
| CWE-693 | Protection Mechanism Failure | Bypass jailbreak detection, Frida detection |
