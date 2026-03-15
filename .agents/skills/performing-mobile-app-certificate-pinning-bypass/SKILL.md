---
name: performing-mobile-app-certificate-pinning-bypass
description: >
  Bypasses SSL/TLS certificate pinning implementations in Android and iOS applications to enable
  traffic interception during authorized security assessments. Covers OkHttp, TrustManager,
  NSURLSession, and third-party pinning library bypass techniques using Frida, Objection, and
  custom scripts. Activates for requests involving certificate pinning bypass, SSL pinning defeat,
  mobile TLS interception, or proxy-resistant app testing.
domain: cybersecurity
subdomain: mobile-security
author: mahipal
tags: [mobile-security, android, ios, certificate-pinning, frida, penetration-testing]
version: 1.0.0
license: Apache-2.0
---
# Performing Mobile App Certificate Pinning Bypass

## When to Use

Use this skill when:
- Mobile app refuses connections through a proxy due to certificate pinning
- Performing authorized security testing requiring HTTPS traffic interception
- Assessing the strength and bypass difficulty of pinning implementations
- Evaluating defense-in-depth of mobile app network security

**Do not use** to bypass pinning on apps without explicit testing authorization.

## Prerequisites

- Burp Suite configured as proxy with listener on all interfaces
- Rooted Android device or jailbroken iOS device
- Frida server running on target device
- Objection installed (`pip install objection`)
- Target app installed and reproducing the pinning behavior

## Workflow

### Step 1: Identify Pinning Implementation

**Android pinning methods to identify:**
```
1. Network Security Config (res/xml/network_security_config.xml)
   <pin-set> with certificate hash pins

2. OkHttp CertificatePinner
   CertificatePinner.Builder().add("api.target.com", "sha256/...")

3. Custom TrustManager
   X509TrustManager overrides in code

4. Third-party libraries
   - TrustKit
   - Certificate Transparency checks
```

**iOS pinning methods:**
```
1. NSURLSession delegate (URLSession:didReceiveChallenge:)
2. ATS (App Transport Security) with custom trust evaluation
3. TrustKit framework
4. Alamofire ServerTrustPolicy
5. Custom SecTrust evaluation
```

### Step 2: Bypass with Objection (Quickest Approach)

```bash
# Android
objection --gadget com.target.app explore
android sslpinning disable

# iOS
objection --gadget com.target.app explore
ios sslpinning disable
```

Objection hooks common pinning implementations including OkHttp CertificatePinner, TrustManagerImpl, NSURLSession delegate methods, and SecTrust evaluation.

### Step 3: Bypass with Custom Frida Scripts

**Android - Universal SSL Pinning Bypass:**
```javascript
// android_ssl_bypass.js
Java.perform(function() {
    // Bypass TrustManagerImpl
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain,
        host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] Bypassing TrustManagerImpl for: " + host);
        return untrustedChain;
    };

    // Bypass OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation =
            function(hostname, peerCertificates) {
                console.log("[+] Bypassing OkHttp3 pinning for: " + hostname);
                return;
            };
    } catch(e) {}

    // Bypass custom X509TrustManager
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustManager = Java.registerClass({
        name: "com.bypass.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // Bypass SSLContext
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation =
        function(km, tm, sr) {
            console.log("[+] Replacing TrustManagers in SSLContext.init");
            this.init(km, [TrustManager.$new()], sr);
        };

    // Bypass NetworkSecurityConfig (Android 7+)
    try {
        var NetworkSecurityConfig = Java.use(
            "android.security.net.config.NetworkSecurityConfig");
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
            return true;
        };
    } catch(e) {}

    console.log("[*] SSL pinning bypass loaded");
});
```

```bash
frida -U -f com.target.app -l android_ssl_bypass.js --no-pause
```

**iOS - Universal SSL Pinning Bypass:**
```javascript
// ios_ssl_bypass.js
if (ObjC.available) {
    // Bypass NSURLSession delegate
    var resolver = new ApiResolver("objc");
    resolver.enumerateMatches(
        "-[* URLSession:didReceiveChallenge:completionHandler:]", {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    var completionHandler = new ObjC.Block(args[4]);
                    var NSURLSessionAuthChallengeUseCredential = 0;
                    var trust = new ObjC.Object(args[3])
                        .protectionSpace().serverTrust();
                    var credential = ObjC.classes.NSURLCredential
                        .credentialForTrust_(trust);
                    completionHandler.invoke(NSURLSessionAuthChallengeUseCredential,
                        credential);
                }
            });
        },
        onComplete: function() {}
    });

    // Bypass SecTrustEvaluate
    var SecTrustEvaluateWithError = Module.findExportByName(
        "Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(
            function(trust, error) {
                return 1;  // Always return true
            }, "bool", ["pointer", "pointer"]
        ));
    }

    console.log("[*] iOS SSL pinning bypass loaded");
}
```

### Step 4: Handle Advanced Pinning

For apps using advanced pinning (TrustKit, custom binary checks):

```bash
# Identify the specific pinning library
frida-trace -U -n TargetApp -m "*[*Trust*]" -m "*[*Pin*]" -m "*[*SSL*]" -m "*[*Certificate*]"

# Hook the identified validation function
# Custom Frida script targeting the specific implementation
```

### Step 5: Verify Bypass Success

After applying the bypass:
1. Configure device proxy to Burp Suite
2. Open target app and navigate through authenticated flows
3. Verify HTTPS traffic appears in Burp Suite HTTP History
4. Check for any remaining pinned connections that are not captured

## Key Concepts

| Term | Definition |
|------|-----------|
| **Certificate Pinning** | Restricting accepted server certificates to a known set, preventing MITM via rogue CA certificates |
| **Public Key Pinning** | Pinning the server's public key hash rather than the full certificate, surviving certificate rotation |
| **Network Security Config** | Android XML configuration for declaring trust anchors, pins, and cleartext policy per-domain |
| **TrustKit** | Open-source library implementing certificate pinning with reporting for both Android and iOS |
| **HPKP Deprecation** | HTTP Public Key Pinning header was deprecated in browsers but concept persists in mobile apps |

## Tools & Systems

- **Objection**: Pre-built pinning bypass for common libraries (OkHttp, NSURLSession, TrustKit)
- **Frida**: Custom JavaScript hooks targeting specific pinning implementations
- **apktool**: APK decompilation for identifying pinning in Network Security Config
- **SSLUnpinning (Xposed)**: Xposed framework module for system-wide pinning bypass on Android
- **ssl-kill-switch2**: iOS tweak for disabling SSL pinning system-wide on jailbroken devices

## Common Pitfalls

- **Certificate transparency**: Some apps check CT logs in addition to pinning. May need to bypass CT verification separately.
- **Multi-layer pinning**: Apps may implement pinning at multiple levels (OkHttp + custom TrustManager). Bypass all layers.
- **Binary-level pinning**: Some apps validate certificates in native C/C++ code, which requires Interceptor.attach at native function addresses rather than Java/ObjC hooks.
- **Dynamic pinning updates**: Apps using TrustKit or similar may fetch updated pins from a server. Monitor for pin rotation during testing.
