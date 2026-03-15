# Workflows: Dynamic Analysis of Android App

## Workflow 1: Complete Android Dynamic Assessment

```
[Setup Frida Server] --> [Enumerate app surface] --> [Hook sensitive methods]
                                                            |
                                             +--------------+--------------+
                                             |              |              |
                                      [Auth hooks]   [Crypto hooks]  [Network hooks]
                                      [Login flow]   [Cipher ops]    [API calls]
                                      [Token mgmt]   [Key generation] [URL requests]
                                             |              |              |
                                             +--------------+--------------+
                                                            |
                                                     [Root detection test]
                                                     [Tamper detection test]
                                                     [Debug detection test]
                                                            |
                                                     [Memory/heap analysis]
                                                     [Extract runtime secrets]
                                                            |
                                                     [Document findings]
```

## Workflow 2: Protection Bypass Pipeline

```
[App refuses to run] --> [Identify protection]
                               |
              +----------------+----------------+
              |                |                |
       [Root detection]  [Frida detection]  [Emulator detection]
              |                |                |
       [File checks?]   [Port scan?]      [Build.prop?]
       [su binary?]     [Memory scan?]    [IMEI check?]
       [RootBeer?]      [Process name?]   [Sensor data?]
              |                |                |
       [Bypass script]  [Custom Frida]    [Prop override]
              |                |                |
              +----------------+----------------+
                               |
                        [Verify bypass works]
                        [Continue assessment]
```

## Decision Matrix: Hooking Strategy

| Scenario | Tool | Approach |
|----------|------|----------|
| Quick reconnaissance | Objection | `android hooking watch class` |
| Specific method analysis | Frida script | Custom JavaScript hook |
| Crypto algorithm discovery | frida-trace | Auto-trace javax.crypto.* |
| Memory forensics | Objection | `memory search` / `memory dump` |
| IPC testing | Drozer | Module-based component testing |
| Network analysis | Frida + Burp | Hook + proxy combination |
