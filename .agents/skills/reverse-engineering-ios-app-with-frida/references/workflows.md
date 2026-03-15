# Workflows: iOS Reverse Engineering with Frida

## Workflow 1: Full iOS RE Pipeline

```
[Obtain IPA/binary] --> [Decrypt FairPlay] --> [Static analysis] --> [Dynamic analysis]
                              |                      |                      |
                       [frida-ios-dump]        [class-dump]          [frida-trace]
                       [Clutch]                [Ghidra]              [Custom hooks]
                                               [Hopper]             [Method interception]
                                                                           |
                                                                    [Extract secrets]
                                                                    [Map logic flow]
                                                                    [Document findings]
```

## Workflow 2: Crypto Key Extraction

```
[Hook CommonCrypto] --> [Capture CCCrypt calls] --> [Extract key material]
                              |
                       [Log algorithm, mode, IV]
                       [Log input/output data]
                              |
                       [Reconstruct protocol]
                       [Document encryption scheme]
```

## Decision Matrix: iOS RE Approach

| Binary Type | Static Tool | Dynamic Tool | Notes |
|-------------|------------|-------------|-------|
| Objective-C | class-dump + Ghidra | Frida ObjC.classes | Full runtime visibility |
| Swift (NSObject-based) | dsdump + Ghidra | Frida ObjC.classes | Partial visibility |
| Pure Swift | Ghidra + Swift demangling | Frida Module.enumerateExports | Limited runtime access |
| C/C++ native | Ghidra | Frida Interceptor.attach | Address-based hooking |
