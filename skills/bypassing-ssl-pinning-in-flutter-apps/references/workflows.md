# Workflows: Bypassing SSL Pinning in Flutter Apps

## Why Flutter is different

Native Android/iOS apps use the platform networking + trust store, so a user CA
plus Objection/Frida "universal" hooks usually suffices. Flutter apps route
`dart:io` `HttpClient` traffic through a **statically-linked BoringSSL** inside
the Flutter engine binary:

- Android: `lib/<abi>/libflutter.so`
- iOS: `Frameworks/Flutter.framework/Flutter`

The engine does **not** consult the OS proxy settings and validates certificates
in native code, so proxy-only or Java/ObjC-layer bypasses fail.

## Tooling

| Tool | Purpose | Source |
|------|---------|--------|
| reFlutter | Patch engine to disable cert check + force a fixed proxy | https://github.com/Impact-I/reFlutter |
| Frida | Runtime hook of the BoringSSL verify routine in the engine binary | https://frida.re |
| disable-flutter-tls-verification | Maintained Frida pattern set for the verify function | https://github.com/NVISOsecurity/disable-flutter-tls-verification |
| blutter | Recover Dart snapshot symbols from `libapp.so` | https://github.com/worawit/blutter |
| PCAPdroid | On-device VPN capture (no root) emitting a SOCKS5 stream | https://github.com/emanuele-f/PCAPdroid |
| gost | SOCKS5→HTTP bridge with per-CIDR bypass, feeds capture into Burp | https://github.com/go-gost/gost |

## PCAPdroid + gost capture chain

When the app ignores the proxy (Flutter Dart stack) *and* uses native SDKs
(Firebase) that you do not want to MITM, a VPN-capture + SOCKS-bridge chain
catches everything and routes selectively:

```
app → PCAPdroid VPN (tun0) → SOCKS5 :1080 → adb reverse → gost → Burp :8083
                                                              └→ (bypass CIDRs) → direct to Google
```

```bash
# phone: PCAPdroid in VPN mode, SOCKS5 out to localhost:1080
adb reverse tcp:1080 tcp:1080
# host: gost bridges SOCKS5 → Burp HTTP proxy, bypassing Google/Firebase CIDRs
# current Google ranges: https://www.gstatic.com/ipranges/goog.json
GOOG="142.250.0.0/15,172.217.0.0/16,216.58.192.0/19,172.253.0.0/16"
gost -L socks5://0.0.0.0:1080 -F "http://127.0.0.1:8083?bypass=${GOOG}"
```

Burp has no inbound SOCKS listener, so `gost` translates PCAPdroid's SOCKS5 stream
into the HTTP proxy form Burp understands. The `bypass=` rule sends Google/Firebase
traffic straight to Google with the real certificate.

## Why Firebase is routed around the proxy, not bypassed

Firebase (FlutterFire) runs on the **native** platform SDK, not Dart. reFlutter
only patches `libflutter.so`, so it never touches Firebase's TLS validation, which
checks against the system trust store. Under blanket MITM the native SDK sees
Burp's CA instead of Google's real cert and rejects it — phone/OTP login and App
Check break, blocking the rest of the test.

The correct handling is routing, not an auth bypass: exclude Google/Firebase CIDRs
from Burp (the `bypass=` rule) so those requests reach real Google servers and
authenticate legitimately, while the app's first-party API traffic still flows
through Burp for inspection and tampering.

## reFlutter workflow (Android)

```bash
pip install reflutter
reflutter target.apk          # option 1 = traffic monitoring; enter BURP_IP:PORT
zipalign -p 4 release.RE.apk aligned.apk
uber-apk-signer -a aligned.apk
adb install -r <signed.apk>
```

On the device, set the Burp proxy listener to the IP:PORT you gave reFlutter and
enable "invisible" proxying if using transparent redirection.

## reFlutter workflow (iOS)

```bash
reflutter target.ipa          # option 1; enter BURP_IP:PORT
# the patched .app inside release.RE.ipa must be re-signed to install
codesign -f -s "<signing-identity>" Payload/Runner.app   # or Sideloadly
ios-deploy --bundle release.RE.ipa
```

Requires a jailbroken or developer-provisioned device. On a jailbroken device you
can alternatively replace the `Flutter.framework/Flutter` binary in place instead
of re-signing the whole IPA.

## Frida pattern approach (Method B)

The engine binary is stripped, so BoringSSL's certificate-verification routine
(`ssl_verify_peer_cert` in `handshake.cc`, which feeds `ssl_verify_result`) has no
exported symbol. It is located by scanning the module's executable memory for an
instruction **byte pattern**, then neutralised so verification always succeeds.

Patterns are specific to CPU architecture (arm64, arm, x86_64) **and** to the
Flutter engine version, so a pattern that works on one build will not match
another. Two failure modes follow from that, and the second is the dangerous one:

- **Too specific / stale** — no match, the hook never installs, TLS still fails.
  Loud and obvious.
- **Too loose** — matches ordinary function prologues elsewhere in the engine
  (`55 41 57 41 56 41 55 41 54 53` is just `push rbp/r15/r14/r13/r12/rbx` on x64,
  present in many unrelated functions). Every match gets forced to return success,
  so unrelated engine code silently misbehaves and the symptoms look nothing like
  a certificate problem.

For that reason this skill does not bundle its own pattern set. Use the maintained
script from
[NVISOsecurity/disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification),
which tracks per-engine patterns and verifies them against a corpus of engine
binaries (`libflutter_samples/`, checkable with its `verify.py`):

```bash
curl -LO https://raw.githubusercontent.com/NVISOsecurity/disable-flutter-tls-verification/main/disable-flutter-tls.js
frida -U -f com.target.app -l disable-flutter-tls.js --no-pause
# or, without a local copy:
frida -U --codeshare TheDauntless/disable-flutter-tls-v1 -f com.target.app
```

If it finds no match, the target's engine build is not in the upstream sample set.
Hash the engine binary and report it upstream:

```bash
# Android
apktool d target.apk -o target_out && md5sum target_out/lib/arm64-v8a/libflutter.so
# iOS (unencrypted IPA)
md5sum Payload/Runner.app/Frameworks/Flutter.framework/Flutter
```

Then use Method A (reFlutter) for the engagement. Widening a pattern until it
matches is not a fix — it produces the too-loose failure above.

Note that the upstream script covers the Dart/BoringSSL stack only. If the app
also ships a platform-side pinning plugin, combine it with Objection or the
`performing-mobile-app-certificate-pinning-bypass` skill; that is outside this
script's scope.
