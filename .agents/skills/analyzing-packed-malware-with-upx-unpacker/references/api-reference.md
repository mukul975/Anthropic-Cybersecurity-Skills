# API Reference: Packed Malware and UPX Analysis

## UPX - Ultimate Packer for eXecutables

### Syntax
```bash
upx -d <packed_file>                    # Decompress/unpack
upx -d -o <output> <packed_file>        # Unpack to new file
upx -t <file>                           # Test if packed
upx -l <file>                           # List compression info
upx --version                           # Version info
```

### Output Format
```
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    184320 <-     98304   53.33%   win32/pe      malware.exe
```

## pefile - Python PE Analysis

### Usage
```python
import pefile

pe = pefile.PE("sample.exe")

# Section analysis
for section in pe.sections:
    name = section.Name.rstrip(b"\x00").decode()
    entropy = section.get_entropy()
    print(f"{name}: entropy={entropy:.2f}")

# Import analysis
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        print(f"{dll}: {imp.name}")

pe.close()
```

### Packing Indicators
| Indicator | Threshold |
|-----------|-----------|
| Section entropy | > 7.0 (high, likely packed/encrypted) |
| Import count | < 10 (few imports suggest packing) |
| Virtual/Raw ratio | > 5x (large in-memory expansion) |
| Section names | UPX0, UPX1, .packed, .nsp |

## Detect It Easy (DIE) - Packer Identification

### Syntax
```bash
diec <sample.exe>           # CLI scan
diec -j <sample.exe>        # JSON output
```

### Output
```
PE32 executable
  Packer: UPX(3.96)[NRV2B_LE32,best]
  Compiler: MSVC(2019)
```

## PEiD - Packer Identification (Legacy)

### Packer Signatures Database
| Packer | Section Names | Magic Bytes |
|--------|---------------|-------------|
| UPX | UPX0, UPX1, UPX2 | `UPX!` at end of file |
| ASPack | .aspack, .adata | N/A |
| PECompact | .pec1, .pec2 | N/A |
| Themida | Various | Encrypted sections |
| VMProtect | .vmp0, .vmp1 | Virtualized code |

## PEStudio - Static PE Analysis

### Key Indicators
| Check | Description |
|-------|-------------|
| Entropy | Section-level entropy analysis |
| Imports | API import analysis |
| Strings | Embedded string extraction |
| Signatures | Packer/compiler identification |
| Virustotal | Hash-based lookup |

## x64dbg / x32dbg - Dynamic Unpacking

### Generic Unpacking Steps
```
1. Set breakpoint on VirtualAlloc / VirtualProtect
2. Run until breakpoint
3. Check memory map for new RWX regions
4. Step until original entry point (OEP) reached
5. Dump memory at OEP using Scylla plugin
6. Fix import table with Scylla
```

### Key API Breakpoints
| API | Purpose |
|-----|---------|
| `VirtualAlloc` | Memory allocation for unpacked code |
| `VirtualProtect` | Change memory protection (RWX) |
| `LoadLibraryA` | Load DLLs for import resolution |
| `GetProcAddress` | Resolve API addresses |
| `NtWriteVirtualMemory` | Write unpacked code to memory |

## Entropy Interpretation

| Range | Interpretation |
|-------|---------------|
| 0-1 | Nearly empty/uniform data |
| 1-5 | Normal code/data |
| 5-7 | Compressed or obfuscated |
| 7-8 | Encrypted or packed (maximum ~8.0) |
