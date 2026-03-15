# API Reference: iOS App Reverse Engineering with Frida

## Frida CLI Tools

| Command | Description |
|---------|-------------|
| `frida-ps -Ua` | List running apps on USB device |
| `frida -U -n AppName -e "script"` | Attach to app and run script |
| `frida -U -f com.app.bundle -l script.js` | Spawn app with script |
| `frida-trace -U -n AppName -m "*[ClassName *]"` | Trace ObjC methods |
| `frida-discover -U -n AppName` | Discover available functions |

## Frida JavaScript API

| API | Description |
|-----|-------------|
| `ObjC.classes.ClassName` | Access Objective-C class |
| `ObjC.classes.Cls.$ownMethods` | List class methods |
| `Interceptor.attach(target, callbacks)` | Hook native function |
| `Interceptor.replace(target, replacement)` | Replace function implementation |
| `Module.findExportByName(null, "func")` | Find exported C function |
| `ObjC.Object(ptr)` | Wrap pointer as ObjC object |
| `Memory.readUtf8String(ptr)` | Read string from memory |

## Common iOS Security Hooks

| Target | Purpose |
|--------|---------|
| `SSLSetPeerDomainName` | Bypass SSL pinning |
| `NSFileManager fileExistsAtPath:` | Jailbreak detection |
| `CCCrypt` | Intercept encryption calls |
| `NSURLSession` | Monitor network requests |
| `SecItemCopyMatching` | Keychain access |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute frida CLI tools |
| `frida` | >=16.0 | Frida Python bindings |
| `json` | stdlib | Report generation |

## References

- Frida Documentation: https://frida.re/docs/home/
- Frida JavaScript API: https://frida.re/docs/javascript-api/
- objection: https://github.com/sensepost/objection
- OWASP Mobile Testing Guide: https://mas.owasp.org/MASTG/
