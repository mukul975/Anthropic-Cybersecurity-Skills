# API Reference: Go Malware Analysis with Ghidra

## Ghidra Go Analysis Setup

### GoResolver Script (Volexity)
```bash
# Install GoResolver for stripped Go binary function recovery
git clone https://github.com/volexity/GoResolver
# Run against Ghidra project
analyzeHeadless /ghidra_projects MyProject -process go_malware.exe \
  -postScript GoResolver.java
```

### Ghidra Built-in Go Support (10.3+)
```
File > Import > Select Go binary
Analysis > Auto Analyze (includes GolangAnalyzer)
Window > Function Tags > Filter "go."
```

## Go Binary Characteristics

### Build Info Magic
```
Offset in .go.buildinfo section: "\xff Go buildinf:"
```

### gopclntab Magic Bytes
| Go Version | Magic |
|------------|-------|
| 1.2-1.15 | `FB FF FF FF 00 00` |
| 1.16-1.17 | `FA FF FF FF 00 00` |
| 1.18-1.19 | `F0 FF FF FF 00 00` |
| 1.20+ | `F1 FF FF FF 00 00` |

### String Format
Go strings are length-prefixed (not null-terminated):
```
struct GoString {
    char *ptr;      // pointer to string data
    int64 length;   // string length
};
```

## Go-Specific Ghidra Scripts

### GoReSym (Mandiant)
```bash
GoReSym -t -d -p /path/to/binary
# -t: Recover type information
# -d: Dump function metadata
# -p: Print package listing
```

### redress (Go Reverse Engineering)
```bash
redress -src binary.exe           # Reconstruct source tree
redress -pkg binary.exe           # List packages
redress -type binary.exe          # Type information
redress -string binary.exe        # Go string extraction
redress -interface binary.exe     # Interface types
```

## Go Obfuscation Tools

| Tool | Technique | Detection |
|------|-----------|-----------|
| garble | Function name hashing, literal obfuscation | Hash-like symbols, missing debug info |
| gobfuscate | Package/function renaming | Random 8-char names |
| go-strip | Symbol table removal | Missing gopclntab entries |

## Common Go Malware Families

| Family | Type | Notable Packages |
|--------|------|-----------------|
| Sliver | C2 implant | protobuf, grpc, mtls |
| Merlin | C2 agent | http2, jose, websocket |
| Sunlogin/Cobalt | RAT | screenshot, clipboard, keylog |
| BianLian | Ransomware | crypto/aes, filepath.Walk |
| Royal | Ransomware | goroutine-based parallel encryption |

## Key Ghidra Analysis Steps
```
1. Search > For Strings > "go1." (version identification)
2. Search > For Bytes > FB FF FF FF (gopclntab)
3. Symbol Table > Filter "main." (entry points)
4. Navigation > Go To "runtime.main" (program start)
5. Decompiler > Check goroutine spawns (runtime.newproc)
6. Data Types > Apply GoString struct to string references
```
