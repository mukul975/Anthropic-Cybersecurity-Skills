---
name: conducting-mobile-app-penetration-test
description: >
  Conducts penetration testing of iOS and Android mobile applications following the OWASP
  Mobile Application Security Testing Guide (MASTG) to identify vulnerabilities in data storage,
  network communication, authentication, cryptography, and platform-specific security controls.
  The tester performs static analysis of application binaries, dynamic analysis at runtime, and
  API security testing to evaluate the complete mobile attack surface. Activates for requests
  involving mobile app pentest, iOS security assessment, Android security testing, or OWASP
  MASTG assessment.
domain: cybersecurity
subdomain: penetration-testing
tags: [mobile-pentest, OWASP-MASTG, Android-security, iOS-security, mobile-application-security]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Conducting Mobile App Penetration Test

## When to Use

- Testing mobile applications before release to identify security vulnerabilities and data protection issues
- Conducting compliance assessments against OWASP MASVS (Mobile Application Security Verification Standard) levels L1 and L2
- Evaluating the security of mobile banking, healthcare, or government applications handling sensitive data
- Testing mobile apps that interact with backend APIs to assess the end-to-end security of the mobile ecosystem
- Assessing mobile application resistance to reverse engineering, tampering, and runtime manipulation

**Do not use** against mobile applications without written authorization from the application owner, for distributing modified or repackaged applications, or for testing apps on the public app stores without a separate test build.

## Prerequisites

- Target application IPA (iOS) and APK (Android) files or access to download from a private distribution channel
- Rooted Android device or emulator (Genymotion, Android Studio AVD) with Frida, Objection, and Magisk installed
- Jailbroken iOS device or Corellium virtual device with Frida, Objection, and SSL Kill Switch installed
- Static analysis tools: jadx (Android decompilation), Hopper/Ghidra (iOS binary analysis), MobSF (automated scanning)
- Burp Suite Professional configured as proxy for intercepting mobile app traffic with CA certificate installed on the test device

## Workflow

### Step 1: Static Analysis

Analyze the application binary without executing it:

**Android Static Analysis:**
- Decompile the APK: `jadx -d output/ target.apk` to obtain Java/Kotlin source code
- Review `AndroidManifest.xml` for exported components (activities, services, receivers, content providers), permissions, and debuggable flag
- Search for hardcoded secrets: `grep -rn "api_key\|password\|secret\|token\|aws_" output/`
- Identify insecure data storage patterns: SharedPreferences with sensitive data, SQLite databases without encryption, files in external storage
- Check for WebView vulnerabilities: `setJavaScriptEnabled(true)`, `addJavascriptInterface()`, and loading untrusted content
- Run MobSF automated scan: `python manage.py runserver` and upload the APK for automated static analysis

**iOS Static Analysis:**
- Extract the IPA and locate the Mach-O binary
- Use `otool -L <binary>` to list linked frameworks and identify third-party libraries
- Analyze with Ghidra or Hopper for hardcoded URLs, API endpoints, and embedded credentials
- Check Info.plist for App Transport Security (ATS) exceptions that allow insecure HTTP connections
- Review embedded entitlements for excessive capabilities

### Step 2: Network Security Testing

Intercept and analyze all network communications:

- Configure Burp Suite as proxy on the test device and install the Burp CA certificate
- Exercise all application functionality while Burp captures API traffic
- **SSL/TLS validation**: Verify the app validates server certificates properly. If the app fails to connect through the proxy, it may implement certificate pinning.
- **Certificate pinning bypass**:
  - Android: Use Frida script: `frida -U -f com.target.app -l ssl-pinning-bypass.js --no-pause`
  - iOS: Use SSL Kill Switch or Objection: `objection -g "Target App" explore --startup-command "ios sslpinning disable"`
- **API traffic analysis**: Review all API calls for:
  - Sensitive data transmitted without encryption
  - Authentication tokens in URL parameters (visible in logs)
  - Excessive data in API responses beyond what the UI displays
  - Missing or weak authentication on API endpoints
- **WebSocket and custom protocols**: Check for non-HTTP communication channels that may bypass standard proxy interception

### Step 3: Data Storage Analysis

Test for insecure local data storage:

**Android Data Storage:**
- Access app data directory: `/data/data/com.target.app/`
- Check SharedPreferences XML files for stored credentials, tokens, and PII
- Examine SQLite databases: `sqlite3 /data/data/com.target.app/databases/*.db ".dump"`
- Check for sensitive data in application logs: `logcat -d | grep -i "password\|token\|key"`
- Verify that application data is excluded from backups: `android:allowBackup="false"` in AndroidManifest.xml
- Check clipboard for sensitive data leakage

**iOS Data Storage:**
- Examine the Keychain for stored credentials: `objection -g "Target App" explore` then `ios keychain dump`
- Check NSUserDefaults/plist files: `find /var/mobile/Containers/Data/Application/ -name "*.plist" -exec plutil -p {} \;`
- Inspect SQLite databases and Core Data stores for unencrypted sensitive data
- Check for data leaking through screenshots (iOS captures screenshots during app backgrounding)
- Verify data protection class: sensitive files should use NSFileProtectionComplete

### Step 4: Authentication and Session Management

Test mobile-specific authentication controls:

- **Biometric bypass**: Test if biometric authentication can be bypassed by hooking the authentication callback with Frida to always return success
- **Token storage**: Verify that authentication tokens are stored in the Keychain (iOS) or Android Keystore, not in SharedPreferences or files
- **Session timeout**: Verify that sessions expire after a reasonable idle timeout and that tokens are invalidated server-side on logout
- **Root/jailbreak detection bypass**: Test if the app detects rooted/jailbroken devices and if the detection can be bypassed with Frida or Magisk Hide
- **Deep link abuse**: Test if custom URL schemes or universal links can be used to bypass authentication or access restricted functionality

### Step 5: Runtime Manipulation

Test the application's resistance to runtime attacks:

- **Frida hooking**: Use Frida to hook and modify application functions at runtime:
  - Bypass root detection: hook the detection function to return false
  - Modify return values of authentication checks
  - Intercept encryption functions to capture plaintext data before encryption
  - Bypass certificate pinning by hooking SSL verification
- **Method swizzling** (iOS): Use Frida to replace Objective-C method implementations
- **Intent manipulation** (Android): Send crafted intents to exported components: `adb shell am start -n com.target.app/.InternalActivity -e "user_id" "admin"`
- **Tampering detection**: Modify the APK/IPA (add code, change resources), re-sign, and install. Verify whether the app detects tampering.

## Key Concepts

| Term | Definition |
|------|------------|
| **OWASP MASTG** | Mobile Application Security Testing Guide; comprehensive manual for mobile app security testing covering both iOS and Android platforms |
| **Certificate Pinning** | A mobile security control that restricts which TLS certificates the app trusts, preventing man-in-the-middle attacks through proxy interception |
| **Frida** | Dynamic instrumentation toolkit that allows injection of JavaScript into running processes to hook functions, modify behavior, and bypass security controls |
| **Root/Jailbreak Detection** | Application-level checks to detect if the device has been modified to grant root access, typically blocking app usage on compromised devices |
| **Android Keystore** | Hardware-backed credential storage on Android that protects cryptographic keys and secrets from extraction even on rooted devices |
| **App Transport Security (ATS)** | iOS security feature that enforces HTTPS connections by default; ATS exceptions may indicate insecure network communication |
| **Deep Links** | URL schemes that open specific screens within a mobile application, which may bypass normal navigation and authentication flows if not properly validated |

## Tools & Systems

- **Frida / Objection**: Dynamic instrumentation tools for hooking functions, bypassing security controls, and manipulating application behavior at runtime
- **MobSF (Mobile Security Framework)**: Automated static and dynamic analysis platform for Android and iOS applications
- **jadx**: Android decompiler that converts APK bytecode to readable Java source code for manual code review
- **Burp Suite Professional**: HTTP proxy for intercepting and modifying mobile app API traffic after bypassing certificate pinning

## Common Scenarios

### Scenario: Mobile Banking Application Security Assessment

**Context**: A bank is launching a new mobile banking app for iOS and Android. The app handles account viewing, fund transfers, bill payment, and check deposit. OWASP MASVS L2 compliance is required due to the financial data handled.

**Approach**:
1. Static analysis of the Android APK reveals API endpoints, a hardcoded staging server URL, and an AWS API key in a configuration file
2. Certificate pinning is implemented but bypassed with Frida SSL pinning bypass script
3. API traffic analysis reveals that the balance check endpoint returns all account numbers associated with the user, not just the requested account
4. Local data storage analysis finds that the app caches the last 10 transactions in an unencrypted SQLite database
5. Biometric authentication bypass: Frida hook on the biometric callback always returns success, granting access without fingerprint
6. Root detection is present but bypassed with Magisk Hide module, allowing the app to run on a rooted device with full data access

**Pitfalls**:
- Testing only on an emulator and missing hardware-specific security features (Android Keystore hardware backing, iOS Secure Enclave)
- Not testing both iOS and Android versions, as they may have different implementations and different vulnerabilities
- Ignoring the backend API security because it was "tested separately" when the mobile app may call API endpoints differently than the web app
- Failing to test certificate pinning bypass, resulting in an incomplete network analysis

## Output Format

```
## Finding: Biometric Authentication Bypass via Frida Instrumentation

**ID**: MOB-003
**Severity**: High (CVSS 7.7)
**Platform**: Android and iOS
**OWASP MASVS**: MASVS-AUTH-2 (Biometric Authentication)

**Description**:
The mobile banking app's biometric authentication can be bypassed using Frida
dynamic instrumentation. The authentication callback function accepts a boolean
result from the biometric API, which can be hooked and forced to return true
without presenting a valid fingerprint or face scan.

**Proof of Concept (Android)**:
frida -U -f com.bank.mobileapp -l bypass-biometric.js --no-pause

// bypass-biometric.js
Java.perform(function() {
  var BiometricCallback = Java.use("com.bank.mobileapp.auth.BiometricCallback");
  BiometricCallback.onAuthenticationSucceeded.implementation = function(result) {
    console.log("[*] Biometric bypassed");
    this.onAuthenticationSucceeded(result);
  };
});

**Impact**:
An attacker with physical access to an unlocked device can bypass biometric
authentication and access the victim's bank accounts, initiate transfers,
and view financial data without biometric verification.

**Remediation**:
1. Implement server-side biometric verification using Android BiometricPrompt
   CryptoObject tied to a Keystore key
2. Require the biometric operation to decrypt a server-side challenge, making
   client-side bypass ineffective
3. Add runtime integrity checks to detect Frida and other instrumentation frameworks
4. Implement step-up authentication for high-risk operations (transfers > threshold)
```
