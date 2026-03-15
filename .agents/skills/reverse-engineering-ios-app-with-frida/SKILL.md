---
name: reverse-engineering-ios-app-with-frida
description: >
  Reverse engineers iOS applications using Frida dynamic instrumentation to understand internal
  logic, extract encryption keys, bypass security controls, and discover hidden functionality
  without source code access. Use when performing authorized iOS penetration testing, analyzing
  proprietary protocols, understanding obfuscated logic, or extracting runtime secrets from
  iOS binaries. Activates for requests involving iOS reverse engineering, Frida iOS hooking,
  Objective-C/Swift method tracing, or iOS binary analysis.
domain: cybersecurity
subdomain: mobile-security
author: mahipal
tags: [mobile-security, ios, frida, reverse-engineering, owasp-mobile, penetration-testing]
version: 1.0.0
license: Apache-2.0
---
# Reverse Engineering iOS App with Frida

## When to Use

Use this skill when:
- Analyzing iOS app internals during authorized security assessments without source code
- Extracting encryption keys, API secrets, or proprietary protocol details from running iOS apps
- Understanding obfuscated Swift/Objective-C logic through runtime method tracing
- Bypassing complex security mechanisms (jailbreak detection, anti-tampering, anti-debugging)

**Do not use** this skill for unauthorized reverse engineering that violates terms of service or intellectual property law.

## Prerequisites

- Jailbroken iOS device with Frida server installed via Cydia/Sileo, or non-jailbroken device with Frida Gadget-injected IPA
- Python 3.10+ with `frida-tools` (`pip install frida-tools`)
- USB connection to iOS device
- class-dump or dsdump for Objective-C header extraction
- Hopper Disassembler or Ghidra for static binary analysis (complementary)
- Knowledge of Objective-C runtime and Swift name mangling

## Workflow

### Step 1: Extract and Analyze the Binary

```bash
# On jailbroken device, find app binary
ssh root@<device_ip>
find /var/containers/Bundle/Application/ -name "TargetApp" -type f

# Pull decrypted binary (apps from App Store are encrypted with FairPlay)
# Use frida-ios-dump or Clutch for decryption
pip install frida-ios-dump
dump.py com.target.app

# Extract Objective-C class headers
class-dump -H decrypted_binary -o headers/
ls headers/  # Lists all class header files
```

### Step 2: Enumerate Classes and Methods at Runtime

```javascript
// enumerate_classes.js - List all loaded classes
Java.perform(function() {});  // N/A for iOS

// iOS uses ObjC runtime
if (ObjC.available) {
    var classes = ObjC.classes;
    for (var className in classes) {
        if (className.indexOf("Target") !== -1 ||
            className.indexOf("Auth") !== -1 ||
            className.indexOf("Crypto") !== -1) {
            console.log("[Class] " + className);

            // List methods
            var methods = classes[className].$ownMethods;
            for (var i = 0; i < methods.length; i++) {
                console.log("  [Method] " + methods[i]);
            }
        }
    }
}
```

```bash
frida -U -n TargetApp -l enumerate_classes.js
```

### Step 3: Trace Method Calls with frida-trace

```bash
# Trace all methods of a class
frida-trace -U -n TargetApp -m "*[TargetAuth *]"

# Trace specific patterns
frida-trace -U -n TargetApp -m "*[*Crypto* *]"
frida-trace -U -n TargetApp -m "*[*KeyChain* *]"
frida-trace -U -n TargetApp -m "*[*Token* *]"

# Trace Swift methods (mangled names)
frida-trace -U -n TargetApp -m "*[*$s*Auth*]"
```

### Step 4: Hook and Modify Method Behavior

```javascript
// hook_auth.js - Intercept authentication logic
if (ObjC.available) {
    // Hook Objective-C method
    var AuthManager = ObjC.classes.AuthManager;
    if (AuthManager) {
        Interceptor.attach(AuthManager["- validateToken:"].implementation, {
            onEnter: function(args) {
                // args[0] = self, args[1] = selector, args[2+] = method args
                var token = new ObjC.Object(args[2]);
                console.log("[Auth] validateToken called with: " + token.toString());
            },
            onLeave: function(retval) {
                console.log("[Auth] validateToken returned: " + retval);
                // Optionally modify return value
                // retval.replace(ptr(1));  // Force return true
            }
        });
    }

    // Hook CommonCrypto for encryption analysis
    var CCCrypt = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                this.operation = args[0].toInt32();  // 0=encrypt, 1=decrypt
                this.algorithm = args[1].toInt32();  // 0=AES128, 1=DES, 2=3DES
                this.keyLength = args[4].toInt32();
                this.key = Memory.readByteArray(args[3], this.keyLength);
                console.log("[CCCrypt] Op:" + (this.operation === 0 ? "Encrypt" : "Decrypt"));
                console.log("[CCCrypt] Key: " + hexify(this.key));
            },
            onLeave: function(retval) {
                console.log("[CCCrypt] Status: " + retval);
            }
        });
    }
}

function hexify(buffer) {
    var bytes = new Uint8Array(buffer);
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(("0" + bytes[i].toString(16)).slice(-2));
    }
    return hex.join("");
}
```

### Step 5: Analyze Swift Code

```javascript
// swift_analysis.js - Hook Swift methods
// Swift methods use name mangling: $s<module><class><method>
// Use frida-trace to discover actual mangled names first

if (ObjC.available) {
    // Swift classes that inherit from NSObject are accessible via ObjC runtime
    var swiftClasses = Object.keys(ObjC.classes).filter(function(name) {
        return name.indexOf("_TtC") === 0 || name.indexOf("TargetApp.") !== -1;
    });

    swiftClasses.forEach(function(className) {
        console.log("[Swift] " + className);
        var methods = ObjC.classes[className].$ownMethods;
        methods.forEach(function(method) {
            console.log("  " + method);
        });
    });
}

// For pure Swift (non-ObjC-bridged), use Module.enumerateExports
Module.enumerateExports("TargetApp", {
    onMatch: function(exp) {
        if (exp.name.indexOf("Auth") !== -1 || exp.name.indexOf("Crypto") !== -1) {
            console.log("[Export] " + exp.name + " @ " + exp.address);
        }
    },
    onComplete: function() {}
});
```

### Step 6: Extract Secrets and Proprietary Data

```javascript
// extract_secrets.js
if (ObjC.available) {
    // Hook NSUserDefaults
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    Interceptor.attach(NSUserDefaults["- objectForKey:"].implementation, {
        onEnter: function(args) {
            this.key = new ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (retval.isNull()) return;
            var value = new ObjC.Object(retval);
            console.log("[NSUserDefaults] " + this.key + " = " + value.toString());
        }
    });

    // Hook Keychain access
    var SecItemCopyMatching = Module.findExportByName("Security", "SecItemCopyMatching");
    Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
            var query = new ObjC.Object(args[0]);
            console.log("[Keychain] Query: " + query.toString());
        },
        onLeave: function(retval) {
            console.log("[Keychain] Result: " + retval);
        }
    });
}
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Objective-C Runtime** | Dynamic runtime enabling method dispatch, class introspection, and method swizzling at runtime |
| **Swift Name Mangling** | Compiler-applied encoding of Swift function signatures into linker-compatible symbol names |
| **FairPlay DRM** | Apple's encryption applied to App Store binaries; must be decrypted before static analysis |
| **class-dump** | Tool extracting Objective-C class declarations from Mach-O binaries for header-level analysis |
| **CommonCrypto** | Apple's C-level cryptographic library; primary target for encryption key extraction via Frida hooks |

## Tools & Systems

- **Frida**: Dynamic instrumentation framework for iOS runtime hooking and method interception
- **frida-trace**: Automated tracing utility that generates handler stubs for matched methods
- **frida-ios-dump**: Tool for decrypting FairPlay-protected iOS apps via memory dumping
- **class-dump / dsdump**: Objective-C header extraction from Mach-O binaries
- **Ghidra**: NSA's reverse engineering framework for static ARM64 binary analysis of iOS apps

## Common Pitfalls

- **FairPlay encryption**: Apps downloaded from the App Store are encrypted. You must decrypt before static analysis. Use frida-ios-dump on a jailbroken device.
- **Swift-only classes**: Pure Swift classes without `@objc` annotation are not visible through `ObjC.classes`. Use `Module.enumerateExports()` instead.
- **Stripped binaries**: Release builds strip debug symbols. Combine frida-trace with class-dump output for effective analysis.
- **Anti-Frida measures**: Sophisticated apps check for Frida artifacts (frida-server process, Frida agent strings in memory, injected libraries in dyld). Use stealthy Frida builds or Frida Gadget injection.
