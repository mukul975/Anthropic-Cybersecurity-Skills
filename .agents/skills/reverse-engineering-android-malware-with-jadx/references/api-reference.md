# API Reference: Android Malware Reverse Engineering with JADX Agent

## Overview

Reverse engineers Android APKs using apktool for manifest extraction, JADX for Java decompilation, and regex-based source code analysis for malicious patterns (C2 URLs, SMS interception, overlay attacks).

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| hashlib | stdlib | APK hash computation |
| xml.etree | stdlib | AndroidManifest.xml parsing |

## External Tools Required

| Tool | Purpose |
|------|---------|
| apktool | APK disassembly and manifest extraction |
| jadx | DEX to Java decompilation with deobfuscation |

## Core Functions

### `compute_apk_hashes(apk_path)`
Generates MD5 and SHA-256 hashes for APK identification.

### `extract_manifest(apk_path, output_dir)`
Extracts AndroidManifest.xml and parses permissions, activities, services, receivers.
- **Returns**: `dict` with `package`, `permissions`, `activities`, `services`, `receivers`

### `analyze_permissions(permissions)`
Classifies permissions against a list of 16 dangerous Android permissions.
- **Risk**: CRITICAL if SMS/accessibility/device-admin, HIGH if >5 dangerous
- **Returns**: `dict` with categorized permission lists and risk level

### `decompile_with_jadx(apk_path, output_dir)`
Runs JADX with `--deobf` flag for deobfuscated Java source output.
- **Timeout**: 300 seconds

### `search_source_code(source_dir, patterns)`
Searches decompiled Java source for 10 malicious pattern categories.
- **Returns**: `dict[str, list[dict]]` - pattern name to file/match pairs

### `analyze_apk(apk_path, output_base)`
Full pipeline: hashes -> manifest -> permissions -> decompile -> code analysis.

## Malicious Code Patterns

| Pattern | Indicator |
|---------|-----------|
| urls | HTTP/HTTPS C2 server addresses |
| ips | Hardcoded IP addresses |
| exec_commands | Runtime.exec() shell command execution |
| reflection | Class.forName() dynamic class loading |
| dex_loading | DexClassLoader for loading additional code |
| overlay_attack | TYPE_APPLICATION_OVERLAY for phishing overlays |
| accessibility_abuse | AccessibilityService for keylogging/automation |
| sms_intercept | SMS_RECEIVED broadcast interception |

## Dangerous Permissions Checked

READ_SMS, SEND_SMS, RECEIVE_SMS, READ_CONTACTS, CAMERA, RECORD_AUDIO, ACCESS_FINE_LOCATION, READ_PHONE_STATE, BIND_ACCESSIBILITY_SERVICE, BIND_DEVICE_ADMIN, REQUEST_INSTALL_PACKAGES

## Usage

```bash
python agent.py malware.apk
```
