# API Reference: Mobile App Penetration Testing Agent

## Overview

Tests Android mobile applications for OWASP MASTG vulnerabilities: insecure storage, hardcoded secrets, manifest misconfigurations, certificate pinning bypass, and API authorization flaws. For authorized testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | API and cert pinning testing |
| apktool | >=2.7 | APK decompilation (subprocess) |
| adb | - | Android device interaction (subprocess) |

## CLI Usage

```bash
python agent.py --apk target.apk --manifest AndroidManifest.xml \
  --api-url https://api.target.com --auth-token <jwt> --output report.json
```

## Key Functions

### `decompile_apk(apk_path, output_dir)`
Decompiles APK using apktool for static analysis of smali code and resources.

### `extract_strings_from_apk(apk_path)`
Extracts hardcoded sensitive strings (API keys, passwords, tokens, URLs) from APK binary.

### `check_android_manifest(manifest_path)`
Analyzes AndroidManifest.xml for debuggable, allowBackup, exported components, and cleartext traffic settings.

### `test_certificate_pinning(target_url)`
Tests if API connections succeed through a proxy (indicating missing cert pinning).

### `check_insecure_storage_adb()`
Checks shared_prefs, databases, and external storage for sensitive data via adb shell.

### `test_api_endpoints(base_url, endpoints, auth_token)`
Tests API endpoints for authorization bypass by comparing authenticated vs unauthenticated responses.

### `check_root_detection(package_name)`
Inspects the app package for root detection library indicators (RootBeer, SafetyNet).

## OWASP MASTG Coverage

| Category | Test | Function |
|----------|------|----------|
| MASVS-STORAGE | Insecure Data Storage | `check_insecure_storage_adb` |
| MASVS-STORAGE | Hardcoded Credentials | `extract_strings_from_apk` |
| MASVS-NETWORK | Certificate Pinning | `test_certificate_pinning` |
| MASVS-NETWORK | Cleartext Traffic | `check_android_manifest` |
| MASVS-AUTH | API Authorization | `test_api_endpoints` |
| MASVS-RESILIENCE | Root Detection | `check_root_detection` |
