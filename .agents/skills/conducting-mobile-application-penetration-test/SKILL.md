---
name: conducting-mobile-application-penetration-test
description: Perform a mobile application penetration test on Android and iOS apps to identify insecure data storage, certificate pinning bypass, API vulnerabilities, binary protections, and runtime manipulation using Frida, Objection, and MobSF.
domain: cybersecurity
subdomain: penetration-testing
tags: [mobile-pentest, Android, iOS, Frida, Objection, MobSF, OWASP-MASTG, certificate-pinning, APK-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Conducting Mobile Application Penetration Test

## Overview

Mobile application penetration testing evaluates the security of Android and iOS applications following the OWASP Mobile Application Security Testing Guide (MASTG) and Mobile Application Security Verification Standard (MASVS). Testing covers static analysis of the application binary, dynamic runtime analysis, API communication security, data storage assessment, and reverse engineering resistance.

## Prerequisites

- Application APK/IPA file or TestFlight/Play Store access
- Rooted Android device or emulator (Genymotion, Android Studio AVD)
- Jailbroken iOS device or Corellium cloud instance
- Tools: Frida, Objection, MobSF, Jadx, Burp Suite, adb, Ghidra
- OWASP MASTG checklist

## Android Testing

### Static Analysis

```bash
# Decompile APK with jadx
jadx -d output_dir target.apk

# Search for hardcoded secrets
grep -rn "api_key\|secret\|password\|token\|firebase" output_dir/sources/

# Check AndroidManifest.xml
# Look for: exported components, debuggable=true, allowBackup=true
grep -i "exported\|debuggable\|allowBackup\|android:permission" output_dir/resources/AndroidManifest.xml

# MobSF automated static analysis
# Upload APK to MobSF web interface (http://localhost:8000)
# Or use REST API:
curl -F "file=@target.apk" http://localhost:8000/api/v1/upload \
  -H "Authorization: <api_key>"

# Check for insecure network security config
cat output_dir/resources/res/xml/network_security_config.xml
# Look for: cleartextTrafficPermitted="true", trust-anchors with user certs

# Analyze native libraries
find output_dir/resources/lib -name "*.so" -exec strings {} \; | grep -i "key\|secret"
```

### Dynamic Analysis

```bash
# Install on device via adb
adb install target.apk

# Start Frida server on device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Objection — runtime exploration
objection -g com.target.app explore

# Inside Objection:
# List activities and services
android hooking list activities
android hooking list services

# Bypass root detection
android root disable

# Bypass SSL pinning
android sslpinning disable

# Dump keystore
android keystore list

# Enumerate shared preferences
android hooking search classes SharedPreferences

# Monitor clipboard
android clipboard monitor

# Explore filesystem
env
ls /data/data/com.target.app/
file download /data/data/com.target.app/shared_prefs/
file download /data/data/com.target.app/databases/
```

### Data Storage Testing

```bash
# Check shared preferences for sensitive data
adb shell cat /data/data/com.target.app/shared_prefs/*.xml

# Check SQLite databases
adb pull /data/data/com.target.app/databases/app.db
sqlite3 app.db ".dump" | grep -i "password\|token\|session"

# Check for data in external storage
adb shell ls /sdcard/Android/data/com.target.app/

# Check for sensitive data in logs
adb logcat -d | grep -i "token\|password\|session\|api_key"

# Backup extraction
adb backup -apk -shared com.target.app -f backup.ab
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar
```

### Network Traffic Analysis

```bash
# Configure Burp proxy on device
# Settings > WiFi > Proxy > Manual > 192.168.1.100:8080
# Install Burp CA certificate on device

# For apps with certificate pinning:
# Method 1: Objection
objection -g com.target.app explore
android sslpinning disable

# Method 2: Frida script
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# Method 3: Patch APK
# Use apktool to decompile, modify network_security_config.xml, repack
apktool d target.apk -o decompiled/
# Edit res/xml/network_security_config.xml to trust user CAs
apktool b decompiled/ -o patched.apk
jarsigner -keystore my.keystore patched.apk alias_name
```

## iOS Testing

### Static Analysis

```bash
# Decrypt IPA (from jailbroken device)
# Using frida-ios-dump
python3 dump.py com.target.app

# Or using Clutch on device
Clutch -d com.target.app

# Analyze binary with class-dump
class-dump -H TargetApp -o headers/
grep -rn "password\|token\|secret\|apiKey" headers/

# Check Info.plist
plutil -p Payload/TargetApp.app/Info.plist
# Look for: ATS exceptions, URL schemes, exported UTIs

# Check for insecure API connections
grep -i "http://" headers/*.h
grep -i "NSAllowsArbitraryLoads" Payload/TargetApp.app/Info.plist
```

### Dynamic Analysis (iOS)

```bash
# Frida on iOS
frida -U -f com.target.app -l ios_bypass.js --no-pause

# Objection for iOS
objection -g com.target.app explore

# Inside Objection:
ios sslpinning disable
ios jailbreak disable
ios keychain dump
ios plist cat NSUserDefaults
ios cookies get
ios nsurlcredentialstorage dump

# Check Keychain for stored secrets
objection -g com.target.app explore --startup-command 'ios keychain dump'

# Check for data protection classes
objection -g com.target.app explore --startup-command 'ios info binary'
```

### API Testing

```bash
# Through Burp Suite, test captured API calls:

# Authentication bypass
# Modify JWT tokens, test for algorithm confusion (none, HS256 vs RS256)

# IDOR testing
# Change user identifiers in API requests

# Rate limiting
# Brute force OTP/PIN endpoints

# Input validation
# Test for injection in API parameters

# Business logic
# Manipulate prices, quantities, subscription tiers in requests
```

## OWASP MASVS Checklist

| Category | Test | Status |
|----------|------|--------|
| MASVS-STORAGE-1 | Sensitive data in system logs | [ ] |
| MASVS-STORAGE-2 | Sensitive data in backups | [ ] |
| MASVS-STORAGE-3 | Sensitive data in IPC | [ ] |
| MASVS-CRYPTO-1 | Proper cryptographic APIs | [ ] |
| MASVS-AUTH-1 | Local authentication bypass | [ ] |
| MASVS-NETWORK-1 | TLS with trusted CA | [ ] |
| MASVS-NETWORK-2 | Certificate pinning | [ ] |
| MASVS-PLATFORM-1 | Exported components secured | [ ] |
| MASVS-CODE-1 | Code obfuscation | [ ] |
| MASVS-RESILIENCE-1 | Root/jailbreak detection | [ ] |

## References

- OWASP MASTG: https://mas.owasp.org/MASTG/
- OWASP MASVS: https://mas.owasp.org/MASVS/
- Frida: https://frida.re/
- Objection: https://github.com/sensepost/objection
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- JADX: https://github.com/skylot/jadx
