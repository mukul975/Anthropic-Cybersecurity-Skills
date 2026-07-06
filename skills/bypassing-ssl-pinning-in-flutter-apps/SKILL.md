---
name: bypassing-ssl-pinning-in-flutter-apps
description: "Intercept HTTPS traffic from Flutter (Dart) mobile apps that ignore the system proxy and trust store. Covers detecting Flutter builds, forcing traffic through an intercepting proxy (including a PCAPdroid + gost SOCKS bridge), defeating BoringSSL certificate validation with reFlutter and Frida hooks on libflutter.so, and selectively bypassing native services like Firebase so authentication keeps working during interception. For both Android and iOS."
domain: cybersecurity
subdomain: mobile-security
tags:
- mobile-security
- flutter
- ssl-pinning
- reflutter
- frida
- burpsuite
- gost
- firebase
- pcapdroid
- android
- ios
- mitm
version: '1.0'
author: michelle-hartono
license: Apache-2.0
nist_csf:
- PR.DS-02
- PR.DS-01
- ID.RA-01
mitre_attack:
- T1557
- T1040
---
# Bypassing SSL Pinning in Flutter Apps

## Overview

Flutter apps do not use the platform HTTP stack. Dart's `dart:io` `HttpClient` is
built on a statically-linked copy of **BoringSSL** compiled into `libflutter.so`
(Android) or the `Flutter` framework binary (iOS). Two consequences make Flutter
apps resist normal mobile interception:

1. **The system proxy is ignored.** Setting a device/emulator HTTP proxy does not
   route Flutter traffic through Burp/mitmproxy, because Flutter reads no proxy
   configuration by default.
2. **Certificate validation happens inside BoringSSL**, against Flutter's own CA
   handling — installing a user CA in the OS store is not enough, and apps that
   add pinning validate the chain in native code that Objection/`SSLPinningKiller`
   style Java/ObjC hooks never touch.

A third subtlety blocks many real tests: some services use **native** SDKs that do
not go through the Dart stack at all. Firebase (via FlutterFire plugins) is the
common one — it runs on the platform's native Firebase SDK, validates TLS against
the system trust store, and is untouched by a `libflutter.so` patch. Blanket MITM
breaks its auth, so it must be routed *around* the proxy rather than bypassed.

This skill covers reliably getting Flutter HTTPS traffic into an intercepting
proxy, disabling the native certificate check, and keeping native-SDK auth
(Firebase) working while you do it.

## When to Use

**Authorized testing only.** Use only against apps you own or have explicit written
permission to test. Do not run against production systems or third-party apps without
authorization.

- When a mobile pentest target is built with Flutter and Burp/mitmproxy shows no
  HTTPS traffic despite a correctly configured proxy and installed CA.
- When Objection / Frida "universal" Android/iOS SSL-pinning bypass scripts run
  without error but traffic still fails or does not appear.
- When turning on MITM breaks Firebase (or another native SDK) login and locks you
  out of the app.
- When you need to reverse engineer a Flutter app's API calls and business logic.

## Prerequisites

- Rooted Android device / emulator or jailbroken iOS device (for Frida runtime
  hooks). reFlutter's repackaging path works without root on Android.
- `frida` and `frida-tools`, `objection`, `apktool`, `adb`.
- `reFlutter` (`pip install reflutter`), Android signing tools (`uber-apk-signer`
  or `apksigner` + `zipalign`), and — for iOS — `ios-deploy`/Sideloadly and a
  signing identity (`codesign`) to re-sign the patched IPA.
- `gost` and `PCAPdroid` for the VPN-capture + SOCKS-bridge interception path.
- Burp Suite or mitmproxy configured with a listening interface reachable from the
  device.
- (Optional) `blutter` for recovering Dart function/class names from the snapshot.

## Workflow

### Step 1: Confirm the app is Flutter
First pull the installed package off the device, then unzip it and look for the
Flutter engine and Dart snapshot:

```bash
# Android: locate and pull the installed APK (base + any split)
adb shell pm path com.target.app          # prints the on-device apk path(s)
adb pull /data/app/.../base.apk target.apk

# Android
unzip -l target.apk | grep -Ei 'libflutter\.so|libapp\.so|flutter_assets'
# iOS
unzip -l target.ipa | grep -Ei 'Frameworks/Flutter\.framework/Flutter|App\.framework/App'
```

Android is confirmed by `lib/*/libflutter.so` + `libapp.so` (or `flutter_assets/`);
iOS by `Frameworks/Flutter.framework/Flutter` (the engine + BoringSSL) plus
`Frameworks/App.framework/App` (the Dart snapshot, equivalent to `libapp.so`).

### Step 2: Force traffic through the proxy
Because Flutter ignores the system proxy, redirect at a lower layer instead:

- **reFlutter forced proxy (simplest):** reFlutter patches the app to send traffic
  to a fixed `IP:PORT` you specify (see Step 3, Method A).
- **Transparent redirect:** route the device's traffic to your proxy with an
  invisible/transparent proxy — e.g. `iptables` `REDIRECT`, PCAPdroid (Android),
  or a VPN-based capture — and run Burp in invisible proxy mode / mitmproxy in
  transparent mode.
- **VPN capture + SOCKS bridge (robust; also captures native-SDK traffic):**
  capture everything with PCAPdroid in VPN mode and have it emit a SOCKS5 stream,
  then bridge it to your host and into Burp. Burp has no inbound SOCKS listener, so
  put `gost` in the middle as a SOCKS5→HTTP translator:

  ```bash
  adb reverse tcp:1080 tcp:1080          # phone localhost:1080 → host over USB
  # host: gost translates PCAPdroid's SOCKS5 into Burp's HTTP proxy on 8083
  gost -L socks5://0.0.0.0:1080 -F "http://127.0.0.1:8083?bypass=${GOOG}"
  ```

  This path catches Flutter's proxy-blind Dart traffic *and* native-SDK traffic,
  and the `bypass=${GOOG}` rule keeps Firebase/Google working (see Step 4).

### Step 3: Disable BoringSSL certificate validation
Redirection (Step 2) only moves traffic toward Burp — the Dart stack still rejects
Burp's certificate until validation is disabled here, so Step 2 and Step 3 are both
required. Use whichever method fits the engagement:

**Method A — reFlutter (patch & repackage, no runtime hooking):**

Android:
```bash
reflutter target.apk
# choose option 1 (traffic monitoring); enter your Burp IP:PORT when prompted
# output: release.RE.apk  (cert check disabled + proxy forced)
zipalign -p 4 release.RE.apk aligned.apk
uber-apk-signer -a aligned.apk               # or apksigner sign
adb install -r aligned-aligned-debugSigned.apk   # use uber-apk-signer's actual output name
```

iOS (jailbroken or developer-provisioned device):
```bash
reflutter target.ipa
# choose option 1; enter your Burp IP:PORT
# output: release.RE.ipa  (cert check disabled + proxy forced)
# the patched .app must be re-signed before it will install:
codesign -f -s "<signing-identity>" Payload/Runner.app   # or use Sideloadly
ios-deploy --bundle release.RE.ipa                        # install to the connected device
```

**Method B — Frida runtime hook on the engine binary:** hook the BoringSSL
`session_verify_cert_chain` / `ssl_verify_result` routine so it always returns
success. Because the engine (`libflutter.so` / `Flutter.framework`) is stripped,
locate the function by memory **pattern-scanning** the module (patterns are
architecture- and engine-version specific and must be updated per target — see
`references/workflows.md` and `scripts/flutter-tls-bypass.js`):

On a rooted/jailbroken device, start a `frida-server` whose version matches your
host `frida-tools` first:

```bash
frida --version                                    # match this version
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server && su -c '/data/local/tmp/frida-server &'"
```

Then hook the target:

```bash
# Android
frida -U -f com.target.app -l scripts/flutter-tls-bypass.js
# iOS (jailbroken): attach by app process name (often "Runner")
frida -U -n Runner -l scripts/flutter-tls-bypass.js
```

### Step 4: Keep Firebase / native-SDK auth working (selective bypass)
reFlutter only patches the Dart/BoringSSL stack. Firebase and other FlutterFire
plugins run on the **native** platform SDK, which validates TLS against the system
trust store and is untouched by the `libflutter.so` patch. If you MITM *everything*,
those native calls are presented Burp's CA instead of Google's real certificate and
fail — Firebase phone/OTP login and App Check break, locking you out of the app.

The fix is routing, not another bypass: send Google/Firebase traffic **straight to
Google** (real cert, so auth succeeds and App Check is satisfied legitimately) while
still forcing the app's own API traffic through Burp. The `bypass=${GOOG}` rule in
the Step 2 gost command does exactly this:

```bash
# Google/Firebase CIDRs to exclude from Burp.
# Pull current ranges from https://www.gstatic.com/ipranges/goog.json
GOOG="142.250.0.0/15,172.217.0.0/16,216.58.192.0/19,172.253.0.0/16"
gost -L socks5://0.0.0.0:1080 -F "http://127.0.0.1:8083?bypass=${GOOG}"
```

Firebase login now completes against real Google servers, and only the app's
first-party API calls land in Burp for inspection and tampering.

### Step 5: Verify interception
Trigger a login or API-backed screen and confirm requests now appear in Burp/
mitmproxy with a readable body. If TLS still fails, the pattern in Method B is
stale for this engine version — fall back to Method A or update the pattern. If
Firebase login specifically fails, widen the `${GOOG}` bypass ranges (Step 4).

### Step 6: (Optional) Recover Dart symbols for deeper analysis
Run `blutter` against `libapp.so` to reconstruct Dart classes, method names, and
string constants, making it possible to trace endpoints, crypto usage, and
client-side validation logic.

## Key Concepts

| Concept | Detail |
|---------|--------|
| Flutter network stack | Dart `HttpClient` over statically-linked BoringSSL in `libflutter.so`; not the OS TLS stack |
| Proxy blindness | Flutter ignores system HTTP proxy → device-level/transparent redirect required |
| Pinning location | Cert chain verified in native BoringSSL, so Java/ObjC hook bypasses miss it |
| reFlutter | Patches APK/IPA to disable cert check and force a fixed proxy; repackage + resign |
| Pattern scan | `libflutter.so` is stripped; the verify function is found by byte-pattern search, version-specific |
| gost | SOCKS5→HTTP bridge between PCAPdroid and Burp; `bypass=` routes chosen CIDRs (Google/Firebase) direct instead of through Burp |
| Native-SDK services | Firebase/FlutterFire calls run on the native SDK with their own TLS validation — reFlutter does not touch them, so exclude them from MITM to keep auth working |
| blutter | Dumps Dart snapshot symbols from `libapp.so` for reverse engineering |

## Tools & Systems

- **reFlutter** — engine-patching for forced proxy + disabled TLS verification.
- **Frida / frida-tools** — runtime hooking of `libflutter.so`.
- **Burp Suite / mitmproxy** — interception (use invisible/transparent mode with redirects).
- **PCAPdroid** — on-device VPN capture that emits a SOCKS5 stream (no root needed) for proxy-blind and native-SDK traffic.
- **gost** — SOCKS5→HTTP proxy bridge with per-CIDR `bypass=`, used to feed PCAPdroid capture into Burp while letting Firebase/Google traffic pass through untouched.
- **blutter** — Dart snapshot reverse engineering.
- **apktool, apksigner/uber-apk-signer, zipalign, adb** — repackage/sign/install.

## Common Scenarios

- **"Proxy set, CA installed, still no traffic"** → Flutter ignoring proxy; use reFlutter forced proxy or the PCAPdroid + gost bridge (Step 2).
- **"Objection android sslpinning disable does nothing"** → pinning is in native BoringSSL; use Method A or B (Step 3), not Java hooks.
- **"Frida script errors / traffic still 400s after hooking"** → pattern is stale for this engine version; update pattern or switch to reFlutter.
- **"Firebase/Google login stops working the moment I turn on MITM"** → native Firebase SDK rejects Burp's cert; do not try to bypass it — exclude Google/Firebase CIDRs from Burp with gost's `bypass=` (Step 4) so auth completes legitimately.

## Output Format

An interception setup report: app framework confirmation, redirection method used
(reFlutter forced proxy vs PCAPdroid + gost bridge), TLS-bypass method (reFlutter vs
Frida pattern + engine version), which services were excluded from MITM (e.g.
Firebase/Google CIDRs) and why, a sample of captured HTTPS requests/responses, and
any endpoints/secrets recovered via blutter.
