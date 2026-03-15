# Standards Reference: Dynamic Analysis of Android App

## OWASP Mobile Top 10 2024 Mapping

| OWASP ID | Risk | Dynamic Analysis Coverage |
|----------|------|--------------------------|
| M1 | Improper Credential Usage | Intercept credentials at runtime, dump keystore |
| M3 | Insecure Authentication/Authorization | Hook auth methods, observe token generation |
| M5 | Insecure Communication | Monitor network calls, intercept decrypted payloads |
| M7 | Insufficient Binary Protections | Test root detection, Frida detection, tamper checks |
| M8 | Security Misconfiguration | Explore exported components, test IPC endpoints |
| M10 | Insufficient Cryptography | Hook Cipher/MessageDigest to observe crypto operations |

## OWASP MASVS v2.0 Control Mapping

| MASVS Category | Dynamic Test | Method |
|----------------|-------------|--------|
| MASVS-STORAGE | Runtime data extraction | Heap inspection, memory search |
| MASVS-CRYPTO | Algorithm observation | Hook javax.crypto.Cipher |
| MASVS-AUTH | Auth flow analysis | Hook login/token methods |
| MASVS-NETWORK | Traffic monitoring | Hook OkHttp, HttpURLConnection |
| MASVS-PLATFORM | IPC testing | Drozer, intent fuzzing |
| MASVS-RESILIENCE | Protection bypass | Root/Frida/debug detection bypass |

## OWASP MASTG Dynamic Test Cases

| Test ID | Description | Tool |
|---------|-------------|------|
| MASTG-TEST-0001 | Testing Local Storage (Runtime) | Objection, Frida |
| MASTG-TEST-0010 | Testing Custom URL Schemes | Frida hooks, ADB |
| MASTG-TEST-0013 | Testing WebView Security | Hook WebView methods |
| MASTG-TEST-0029 | Testing Root Detection | Frida bypass scripts |
| MASTG-TEST-0038 | Testing Anti-Debugging | ptrace hooks, Frida detection |

## CWE Mappings

| CWE ID | Title | Dynamic Detection |
|--------|-------|-------------------|
| CWE-312 | Cleartext Storage | Memory search for plaintext secrets |
| CWE-319 | Cleartext Transmission | Network method hooking |
| CWE-327 | Broken Crypto Algorithm | Cipher.getInstance() hooking |
| CWE-489 | Active Debug Code | Debug flag detection at runtime |
| CWE-693 | Protection Mechanism Failure | Root/tamper detection bypass |
