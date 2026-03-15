---
name: performing-dynamic-analysis-of-android-app
description: >
  Performs runtime dynamic analysis of Android applications using Frida, Objection, and Android
  Debug Bridge to observe application behavior during execution, intercept function calls, modify
  runtime values, and identify vulnerabilities that static analysis misses. Use when testing Android
  apps for runtime security flaws, hooking sensitive methods, bypassing client-side protections,
  or analyzing obfuscated applications. Activates for requests involving Android dynamic analysis,
  runtime hooking, Frida Android instrumentation, or live app behavior analysis.
domain: cybersecurity
subdomain: mobile-security
author: mahipal
tags: [mobile-security, android, frida, dynamic-analysis, owasp-mobile, penetration-testing]
version: 1.0.0
license: Apache-2.0
---
# Performing Dynamic Analysis of Android App

## When to Use

Use this skill when:
- Static analysis results need runtime validation on an actual Android device
- The target app uses obfuscation (DexGuard, custom packers) that prevents effective static analysis
- Testing requires observing actual API calls, decrypted data, or runtime-generated values
- Assessing root detection, tamper detection, or anti-debugging implementations

**Do not use** this skill on production environments without authorization -- dynamic instrumentation can alter app behavior and trigger security alerts.

## Prerequisites

- Rooted Android device or emulator (Genymotion, Android Studio AVD with writable system)
- Frida server installed on device matching the architecture (arm64, x86_64)
- Python 3.10+ with `frida-tools` and `objection` packages
- ADB configured and device connected
- Target APK installed on device

## Workflow

### Step 1: Setup Frida Server on Android Device

```bash
# Check device architecture
adb shell getprop ro.product.cpu.abi
# Output: arm64-v8a

# Download matching Frida server from GitHub releases
# https://github.com/frida/frida/releases
# Push to device
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify Frida connection
frida-ps -U
```

### Step 2: Enumerate Application Attack Surface

```bash
# List all packages
frida-ps -U -a

# Attach Objection for high-level exploration
objection --gadget com.target.app explore

# List activities, services, receivers
android hooking list activities
android hooking list services
android hooking list receivers

# List loaded classes
android hooking list classes
android hooking search classes com.target.app
```

### Step 3: Hook Sensitive Methods

```bash
# Hook all methods of a class
android hooking watch class com.target.app.auth.LoginManager

# Hook specific method with argument dumping
android hooking watch class_method com.target.app.auth.LoginManager.authenticate --dump-args --dump-return

# Hook crypto operations
android hooking watch class javax.crypto.Cipher --dump-args
android hooking watch class java.security.MessageDigest --dump-args

# Hook network calls
android hooking watch class okhttp3.OkHttpClient --dump-args
android hooking watch class java.net.URL --dump-args
```

### Step 4: Write Custom Frida Scripts for Deep Analysis

```javascript
// hook_crypto.js - Intercept encryption/decryption operations
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.doFinal.overload("[B").implementation = function(input) {
        var mode = this.getAlgorithm();
        console.log("[Cipher] Algorithm: " + mode);
        console.log("[Cipher] Input: " + bytesToHex(input));

        var result = this.doFinal(input);
        console.log("[Cipher] Output: " + bytesToHex(result));
        return result;
    };

    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(("0" + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join("");
    }
});
```

```bash
# Execute custom Frida script
frida -U -f com.target.app -l hook_crypto.js --no-pause
```

### Step 5: Bypass Root Detection

```javascript
// root_bypass.js - Common root detection bypass
Java.perform(function() {
    // Bypass RootBeer library
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() {
        console.log("[RootBeer] isRooted() bypassed");
        return false;
    };

    // Bypass generic file-based root checks
    var File = Java.use("java.io.File");
    var originalExists = File.exists;
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ["/system/app/Superuser.apk", "/system/xbin/su",
                         "/sbin/su", "/system/bin/su", "/data/local/bin/su"];
        if (rootPaths.indexOf(path) >= 0) {
            console.log("[Root] Blocked check for: " + path);
            return false;
        }
        return originalExists.call(this);
    };

    // Bypass SafetyNet/Play Integrity
    try {
        var SafetyNet = Java.use("com.google.android.gms.safetynet.SafetyNetApi");
        console.log("[SafetyNet] Class found - may need additional bypass");
    } catch(e) {}
});
```

### Step 6: Analyze Network Communication at Runtime

```javascript
// network_monitor.js - Monitor all HTTP requests
Java.perform(function() {
    // Hook OkHttp3
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Interceptor = Java.use("okhttp3.Interceptor");
        var Chain = Java.use("okhttp3.Interceptor$Chain");

        console.log("[OkHttp] Monitoring network requests...");

        var Request = Java.use("okhttp3.Request");
        Request.url.implementation = function() {
            var url = this.url();
            console.log("[OkHttp] URL: " + url.toString());
            return url;
        };
    } catch(e) {
        console.log("[OkHttp] Not found, trying HttpURLConnection");
    }

    // Hook HttpURLConnection
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("[URL] Opening: " + this.toString());
        return this.openConnection();
    };
});
```

### Step 7: Extract Decrypted Data and Secrets

```bash
# Using Objection for quick extraction
objection --gadget com.target.app explore

# Dump Android Keystore entries
android keystore list
android keystore dump

# Search heap for sensitive objects
android heap search instances com.target.app.model.User
android heap evaluate <handle> "JSON.stringify(clazz)"

# Memory string search
memory search "password" --string
memory search "api_key" --string
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Dynamic Instrumentation** | Modifying application behavior at runtime by injecting code into the running process |
| **Method Hooking** | Replacing or wrapping function implementations to intercept arguments and return values |
| **Frida Server** | Daemon running on the target device that receives instrumentation commands from the host |
| **Dalvik/ART Runtime** | Android runtime environments; Frida hooks at the ART level for Java/Kotlin methods |
| **Heap Inspection** | Examining live objects in the application's memory heap to extract runtime data |

## Tools & Systems

- **Frida**: Dynamic instrumentation toolkit for injecting JavaScript into native Android processes
- **Objection**: Higher-level Frida wrapper with pre-built Android and iOS security testing commands
- **frida-trace**: Automated method tracing utility for quick reconnaissance of app behavior
- **Drozer**: Android security assessment framework for testing IPC and exported components
- **Android Studio Profiler**: Runtime monitoring for CPU, memory, and network activity

## Common Pitfalls

- **Frida version mismatch**: The Frida server on the device must match the frida-tools version on the host. Version mismatches cause connection failures.
- **Anti-Frida detection**: Some apps detect Frida by checking for the Frida server process, scanning memory for Frida signatures, or monitoring `/proc/self/maps`. Use Frida Gadget injection or custom server builds.
- **Obfuscated class names**: When ProGuard/R8 is applied, class and method names are shortened (e.g., `a.b.c.d()`). Use `android hooking search classes` to discover actual runtime names.
- **Multi-DEX apps**: Large apps split across multiple DEX files may not have all classes loaded at startup. Hook class loaders or use `Java.enumerateLoadedClasses()` after app is fully initialized.
