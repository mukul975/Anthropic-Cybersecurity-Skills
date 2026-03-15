# API Reference: iOS App Security with Objection

## Objection CLI

### Launch
```bash
objection -g com.example.app explore          # Attach to running app
objection -g com.example.app explore -s "command"  # Run startup command
objection patchipa --source app.ipa           # Patch IPA with Frida gadget
```

### Keychain & Data Storage
```bash
ios keychain dump                    # Dump keychain items
ios keychain dump --json             # JSON output
ios cookies get                      # List HTTP cookies
ios nsuserdefaults get               # Read NSUserDefaults
ios plist cat Info.plist             # Read plist file
```

### SSL Pinning
```bash
ios sslpinning disable               # Bypass SSL pinning
ios sslpinning disable --quiet        # Quiet mode
```

### Jailbreak Detection
```bash
ios jailbreak disable                 # Bypass jailbreak detection
ios jailbreak simulate                # Simulate jailbroken device
```

### Hooking
```bash
ios hooking list classes                        # List all classes
ios hooking list classes --include Auth          # Filter classes
ios hooking list class_methods ClassName         # List methods
ios hooking watch method "-[Class method]"       # Watch method calls
ios hooking set return_value "-[Class isJB]" false  # Override return
```

### Filesystem
```bash
ls /                                  # List app sandbox root
ls /Documents                         # List Documents directory
file download /path/to/file local.out  # Download file
file upload local.file /remote/path    # Upload file
```

### Memory
```bash
memory dump all dump.bin              # Dump all memory
memory search "password"              # Search memory for string
memory list modules                   # List loaded modules
memory list exports libModule.dylib   # List module exports
```

## Frida CLI

### Syntax
```bash
frida -U -n AppName                   # Attach by name
frida -U -f com.app.id                # Spawn and attach
frida -U -n AppName -l script.js      # Load script
frida-ps -U                           # List running processes
frida-ls-devices                      # List connected devices
```

### Common Frida Scripts
```javascript
// Hook method and log arguments
ObjC.choose(ObjC.classes.ClassName, {
    onMatch: function(instance) {
        Interceptor.attach(instance['- methodName:'].implementation, {
            onEnter: function(args) {
                console.log('arg1:', ObjC.Object(args[2]));
            }
        });
    }, onComplete: function() {}
});
```

## OWASP Mobile Top 10 (2024)

| ID | Category | Objection Check |
|----|----------|-----------------|
| M1 | Improper Credential Usage | `ios keychain dump` |
| M2 | Inadequate Supply Chain Security | Binary analysis |
| M3 | Insecure Authentication | Hook auth classes |
| M4 | Insufficient Input/Output Validation | Hook input methods |
| M5 | Insecure Communication | `ios sslpinning disable` |
| M6 | Inadequate Privacy Controls | `ios nsuserdefaults get` |
| M7 | Insufficient Binary Protections | Check PIE, ARC, stack canary |
| M8 | Security Misconfiguration | `ios plist cat Info.plist` |
| M9 | Insecure Data Storage | Filesystem + keychain review |
| M10 | Insufficient Cryptography | Hook crypto classes |

## iOS App Sandbox Paths
| Path | Contents |
|------|----------|
| `/Documents` | User-generated data |
| `/Library/Caches` | Cached data |
| `/Library/Preferences` | Plist settings |
| `/tmp` | Temporary files |
| `/Library/Cookies` | Cookie storage |
