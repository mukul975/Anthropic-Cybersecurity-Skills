# API Reference: Volatility 3 Memory Forensics

## Core Syntax
```bash
vol3 -f <memory_dump> <plugin> [options]
vol3 -f memory.dmp --help          # List all plugins
vol3 -f memory.dmp <plugin> --help # Plugin-specific help
```

## Windows Plugins

### Process Analysis
| Plugin | Purpose |
|--------|---------|
| `windows.pslist` | List active processes |
| `windows.pstree` | Process tree (parent-child) |
| `windows.psscan` | Pool-tag scan (finds hidden processes) |
| `windows.cmdline` | Process command-line arguments |
| `windows.envars` | Process environment variables |
| `windows.handles` | Process handle table |

### Code Injection Detection
| Plugin | Purpose |
|--------|---------|
| `windows.malfind` | Detect injected code (RWX memory + PE headers) |
| `windows.hollowfind` | Detect process hollowing |
| `windows.dlllist` | List loaded DLLs per process |
| `windows.ldrmodules` | Detect unlinked DLLs |

### Network
| Plugin | Purpose |
|--------|---------|
| `windows.netscan` | List network connections and listeners |
| `windows.netstat` | Network connections (older Windows) |

### Kernel / Rootkit
| Plugin | Purpose |
|--------|---------|
| `windows.ssdt` | System Service Descriptor Table hooks |
| `windows.callbacks` | Kernel callback registrations |
| `windows.driverscan` | Scan for driver objects |
| `windows.modules` | Loaded kernel modules |
| `windows.idt` | Interrupt Descriptor Table |

### Credentials
| Plugin | Purpose |
|--------|---------|
| `windows.hashdump` | Dump SAM password hashes |
| `windows.cachedump` | Dump cached domain credentials |
| `windows.lsadump` | Dump LSA secrets |

### Registry
| Plugin | Purpose |
|--------|---------|
| `windows.registry.printkey` | Print registry key values |
| `windows.registry.hivelist` | List registry hives |
| `windows.registry.certificates` | Extract certificates |

### File System
| Plugin | Purpose |
|--------|---------|
| `windows.filescan` | Scan for file objects |
| `windows.dumpfiles` | Extract files from memory |
| `windows.memmap` | Dump process memory |

### YARA Scanning
```bash
vol3 -f memory.dmp yarascan.YaraScan --yara-file rules.yar
vol3 -f memory.dmp yarascan.YaraScan --yara-file rules.yar --pid 2184
vol3 -f memory.dmp yarascan.YaraScan --yara-rules "rule Test { strings: $s = \"cmd.exe\" condition: $s }"
```

### Timeline
```bash
vol3 -f memory.dmp timeliner.Timeliner --output-file timeline.csv
```

## Output Options
```bash
vol3 -f memory.dmp windows.pslist --output csv > processes.csv
vol3 -f memory.dmp windows.pslist --output json > processes.json
vol3 -f memory.dmp windows.malfind --dump --pid 2184
```

## Memory Acquisition Tools

| Tool | Platform | Command |
|------|----------|---------|
| WinPmem | Windows | `winpmem_mini_x64.exe memdump.raw` |
| DumpIt | Windows | `DumpIt.exe` (interactive) |
| LiME | Linux | `insmod lime.ko "path=/tmp/mem.lime format=lime"` |
| AVML | Linux | `avml /tmp/memory.lime` |

## Symbols
```bash
# Download symbol packs
# https://downloads.volatilityfoundation.org/volatility3/symbols/
# Place in: volatility3/symbols/
```
