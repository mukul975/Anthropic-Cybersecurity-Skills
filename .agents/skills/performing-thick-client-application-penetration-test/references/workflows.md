# Workflows — Thick Client Penetration Testing

## Attack Flow
```
Application Binary
    │
    ├── Static Analysis (dnSpy/Ghidra/JD-GUI)
    │   ├── Hardcoded credentials
    │   ├── Encryption analysis
    │   └── API endpoint discovery
    │
    ├── Dynamic Analysis (Procmon/Process Hacker)
    │   ├── File system monitoring
    │   ├── Registry access tracking
    │   └── Memory inspection
    │
    ├── Traffic Interception (Burp/Fiddler/Echo Mirage)
    │   ├── API security testing
    │   ├── Certificate pinning bypass
    │   └── Authentication token analysis
    │
    └── Binary Exploitation
        ├── DLL hijacking
        ├── Memory manipulation
        └── Binary patching
```
