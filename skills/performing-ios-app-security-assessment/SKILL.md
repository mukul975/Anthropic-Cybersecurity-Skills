---
name: performing-ios-app-security-assessment
description: 'Performs comprehensive iOS application security assessments using Frida
  for dynamic instrumentation, Objection for runtime exploration, SSL pinning bypass
  for traffic interception, keychain extraction for credential analysis, and IPA static
  analysis for binary-level review. Use when conducting authorized iOS penetration
  tests, evaluating mobile app security posture against OWASP MASTG, or assessing
  iOS app data protection and transport security controls. Activates for requests
  involving iOS app pentesting, Frida-based iOS instrumentation, mobile app SSL pinning
  bypass, or IPA reverse engineering.

  '
domain: cybersecurity
subdomain: mobile-security
author: mukul975
tags:
- mobile-security
- ios
- frida
- objection
- ssl-pinning
- keychain
- ipa-analysis
- owasp-mastg
version: 1.0.0
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.AA-05
- ID.RA-01
- DE.CM-09
mitre_attack:
- T1059
- T1056
- T1036
- T1078
- T1003
---
# Performing iOS App Security Assessment

## Disclaimer

This skill is intended for authorized security testing, penetration testing engagements, CTF competitions, and educational purposes only. Unauthorized access to applications or devices is illegal. Always obtain written authorization before performing any security assessment. Misuse of these techniques may violate computer fraud and abuse laws in your jurisdiction.

## When to Use

Use this skill when:
- Conducting authorized penetration tests of iOS applications against OWASP MASVS/MASTG criteria
- Performing dynamic analysis of iOS apps using Frida instrumentation and Objection runtime exploration
- Bypassing SSL/TLS certificate pinning to intercept and analyze app network traffic through a proxy
- Extracting and auditing iOS Keychain contents for insecure credential storage practices
- Performing static analysis of IPA packages to identify hardcoded secrets, entitlements, and binary protections
- Assessing jailbreak detection and anti-tampering controls in iOS applications

**Do not use** against applications without explicit written authorization. Do not use on production devices containing real user data unless the engagement scope permits it.

## Prerequisites

- Python 3.10+ with pip
- Frida toolkit: `pip install frida-tools frida`
- Objection: `pip install objection`
- Target iOS device (jailbroken with frida-server, or non-jailbroken with patched IPA)
- macOS with Xcode command-line tools (recommended for code signing and ideviceinstaller)
- Burp Suite or mitmproxy for traffic interception after SSL pinning bypass
- For jailbroken devices: SSH access and frida-server running on the device
- For non-jailbroken devices: Apple Developer certificate for IPA re-signing

## Workflow

### Step 1: IPA Static Analysis

Extract and analyze the IPA binary before runtime testing:

```bash
# Unzip IPA for static analysis
unzip target.ipa -d target_app/

# Check binary architectures and protections
otool -hv target_app/Payload/*.app/AppExecutable
otool -l target_app/Payload/*.app/AppExecutable | grep -A4 LC_ENCRYPTION

# Extract Info.plist for entitlements and URL schemes
plutil -p target_app/Payload/*.app/Info.plist

# Search for hardcoded secrets in binary strings
strings target_app/Payload/*.app/AppExecutable | grep -iE "api[_-]?key|secret|password|token|firebase"

# Check embedded provisioning profile
security cms -D -i target_app/Payload/*.app/embedded.mobileprovision

# Identify linked frameworks
otool -L target_app/Payload/*.app/AppExecutable
```

### Step 2: Environment Setup and Frida Attachment

```bash
# For jailbroken device: verify Frida server is running
frida-ps -U

# Spawn target app with Frida
frida -U -f com.target.app --no-pause

# For non-jailbroken device: patch IPA with Frida Gadget
objection patchipa --source target.ipa --codesign-signature "Apple Development: tester@example.com"

# Install patched IPA
ideviceinstaller -i target-patched.ipa

# Attach Objection to running app
objection --gadget "com.target.app" explore
```

### Step 3: SSL Pinning Bypass

Bypass certificate pinning to enable traffic interception:

```bash
# Using Objection's built-in bypass
objection --gadget "com.target.app" explore --startup-command "ios sslpinning disable"

# Using Frida script for more comprehensive bypass
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# Verify bypass by configuring device proxy to Burp Suite
# Device Settings -> Wi-Fi -> HTTP Proxy -> Manual -> <burp_ip>:8080
# Install Burp CA certificate on device via http://<burp_ip>:8080/cert
```

The Frida SSL pinning bypass script hooks into NSURLSession, NSURLConnection, and
AFNetworking/Alamofire trust evaluation delegates to override certificate validation
at the TLS handshake level.

### Step 4: Keychain Extraction and Credential Analysis

```bash
# Dump all accessible keychain items via Objection
ios keychain dump

# Dump keychain with raw data output
ios keychain dump --json

# Check keychain item accessibility attributes
# Items with kSecAttrAccessibleAlways or kSecAttrAccessibleAfterFirstUnlock
# are accessible without device unlock - this is a finding

# Search for specific credential types
ios keychain dump | grep -i "password\|token\|secret\|oauth"

# Inspect NSUserDefaults for sensitive data leaks
ios nsuserdefaults get

# Check for sensitive data in app cookies
ios cookies get
```

### Step 5: Runtime Method Hooking and Analysis

```bash
# List all loaded classes
ios hooking list classes

# Search for security-relevant classes
ios hooking search classes Auth
ios hooking search classes Crypto
ios hooking search classes Biometric
ios hooking search classes Jailbreak

# Hook authentication methods to observe parameters and return values
ios hooking watch method "+[AuthManager validateCredentials:password:]" --dump-args --dump-return

# Monitor biometric authentication (LocalAuthentication framework)
ios hooking watch class LAContext

# Bypass jailbreak detection
ios jailbreak disable

# Search memory for sensitive strings
memory search "Bearer " --string
memory search "password" --string

# Dump loaded modules for third-party library identification
memory list modules
```

### Step 6: Data Storage Assessment

```bash
# List files in app sandbox
env

# Check for SQLite databases with sensitive data
sqlite connect Documents/app.db
sqlite execute query "SELECT name FROM sqlite_master WHERE type='table'"

# Inspect plist files for cached credentials
ios plist cat Library/Preferences/com.target.app.plist

# Check for sensitive data in app caches
find Library/Caches/ -type f

# Monitor pasteboard for credential leakage
ios pasteboard monitor

# Check binary cookies
ios cookies get
```

### Step 7: Network and Transport Security Assessment

After SSL pinning bypass, analyze intercepted traffic:

```bash
# Verify App Transport Security (ATS) configuration in Info.plist
# Check for NSAllowsArbitraryLoads = true (disables ATS)
ios plist cat Info.plist | grep -A5 NSAppTransportSecurity

# Hook URL session delegates to monitor all network calls
ios hooking watch class NSURLSession
ios hooking watch class NSURLSessionConfiguration

# Check for certificate transparency validation
ios hooking search classes CT
ios hooking search classes Certificate
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Frida** | Dynamic instrumentation toolkit that injects a JavaScript engine into target processes, enabling runtime hooking, tracing, and modification of iOS app behavior |
| **Objection** | Runtime mobile exploration toolkit built on Frida providing pre-built commands for common security tests including keychain dump, SSL pinning bypass, and method hooking |
| **SSL Pinning** | Client-side certificate validation that restricts which TLS certificates the app trusts, preventing proxy-based traffic interception; bypassed by hooking trust evaluation functions |
| **Keychain** | iOS secure storage API for credentials and tokens; items have accessibility attributes that control when they can be read (e.g., only when device is unlocked) |
| **IPA** | iOS App Store Package; a ZIP archive containing the app binary, frameworks, assets, and provisioning profile that can be extracted for static analysis |
| **OWASP MASTG** | Mobile Application Security Testing Guide; comprehensive methodology for iOS and Android security testing organized by MASVS verification categories |
| **Frida Gadget** | Shared library (.dylib) injected into IPA for non-jailbroken testing; enables Frida instrumentation without requiring a jailbroken device |
| **Method Swizzling** | Objective-C runtime technique that exchanges method implementations at runtime; used by Frida to intercept and modify method behavior |

## Tools & Systems

- **Frida**: Dynamic instrumentation framework for injecting JavaScript into native app processes at runtime
- **Objection**: High-level Frida-powered mobile security toolkit with pre-built exploration commands
- **frida-tools**: CLI utilities including frida-ps (process listing), frida-trace (method tracing), frida-discover (API discovery)
- **Burp Suite**: HTTP/HTTPS interception proxy used to analyze app traffic after SSL pinning bypass
- **ideviceinstaller**: Cross-platform CLI tool for installing and managing iOS apps over USB
- **otool / rabin2**: Binary analysis tools for inspecting Mach-O headers, linked libraries, and encryption info
- **Cycript / Frida REPL**: Interactive consoles for exploring Objective-C runtime and modifying objects in memory

## Common Pitfalls

- **Frida detection crashes the app**: Some apps implement Frida detection by scanning for frida-server process names, Frida's RPC ports, or gadget signatures. Use `--startup-command` to hook detection checks before they execute, or rename frida-server binary.
- **Keychain scope limitation**: Objection can only access keychain items within the app's keychain access group. System-wide keychain items require jailbreak-level tools like keychain-dumper.
- **Swift name mangling**: Swift method names are mangled in the Objective-C runtime. Use `ios hooking list classes` and grep for demangled names, or use frida-trace with wildcard patterns.
- **App Transport Security enforcement**: ATS may block your proxy connections even after SSL pinning bypass. Verify the Info.plist ATS configuration allows your proxy's certificate chain.
- **Code signing invalidation**: Patching an IPA with Frida Gadget invalidates the original code signature. You need a valid Apple Developer certificate to re-sign the patched IPA.
- **Non-persistent modifications**: All Frida/Objection hooks are runtime-only and reset when the app restarts. Document findings and capture evidence immediately.

## Output Format

```
## Finding: Insecure Keychain Storage with kSecAttrAccessibleAlways

**ID**: IOS-001
**Severity**: High (CVSS 7.5)
**OWASP MASTG**: MASTG-TEST-0055 (Testing Data Storage)
**MASVS Category**: MASVS-STORAGE

**Description**:
The application stores OAuth refresh tokens in the iOS Keychain with
the accessibility attribute kSecAttrAccessibleAlways, making them
readable even when the device is locked or after a reboot without
user authentication.

**Proof of Concept**:
1. Attach Objection to com.target.app: objection --gadget com.target.app explore
2. Execute: ios keychain dump
3. Observe refresh_token item with Accessible: kSecAttrAccessibleAlways
4. Token value is accessible without device unlock

**Impact**:
An attacker with physical access to a locked device or forensic
image can extract OAuth refresh tokens and gain persistent access
to the user's account without knowing device passcode.

**Remediation**:
Store sensitive credentials with kSecAttrAccessibleWhenUnlockedThisDeviceOnly
and enable biometric protection via kSecAccessControlBiometryCurrentSet.
```
