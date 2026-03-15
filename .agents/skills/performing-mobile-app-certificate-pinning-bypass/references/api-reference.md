# API Reference — Performing Mobile App Certificate Pinning Bypass

## Libraries Used
- **subprocess**: Execute frida, objection, apktool, adb commands
- **pathlib**: Read decompiled APK smali files

## CLI Interface
```
python agent.py detect --apk app.apk
python agent.py frida --package com.example.app [--device emulator-5554]
python agent.py objection --package com.example.app
python agent.py proxy
```

## Core Functions

### `detect_pinning_implementation(apk_path)` — Static APK analysis
Decompiles APK with apktool. Searches smali for pinning indicators:
OkHttp CertificatePinner, X509TrustManager, network_security_config,
WebView SSL error handler, Conscrypt TrustManagerImpl, Certificate Transparency.

### `run_frida_bypass(package_name, device_id)` — Dynamic Frida bypass
Injects JavaScript to bypass: TrustManagerImpl.verifyChain, OkHttp CertificatePinner.check,
WebViewClient.onReceivedSslError.

### `run_objection_bypass(package_name)` — Objection framework bypass
Runs `android sslpinning disable` via objection exploration mode.

### `check_proxy_setup()` — Verify interception environment
Checks: Android proxy settings, system CA certificates, user-installed CA certs.

## Pinning Strength Classification
| Level | Criteria |
|-------|----------|
| STRONG | 3+ pinning implementations detected |
| MODERATE | 1-2 implementations |
| NONE | No pinning indicators found |

## Dependencies
```
pip install frida-tools objection
```
System: apktool, adb (Android Debug Bridge)
