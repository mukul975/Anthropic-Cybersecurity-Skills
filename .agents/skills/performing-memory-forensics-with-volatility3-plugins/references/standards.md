# Volatility3 Memory Forensics Standards

## Key Plugins for Malware Analysis
| Plugin | Purpose |
|--------|---------|
| windows.malfind | Detect injected code (RWX regions) |
| windows.psscan | Find hidden/unlinked processes |
| windows.pslist | List active processes from EPROCESS |
| windows.netscan | Network connections and listeners |
| windows.dlllist | Loaded DLLs per process |
| windows.handles | Open handles (files, registry, mutexes) |
| windows.cmdline | Command line arguments |
| windows.svcscan | Windows services |
| windows.yarascan | YARA rule scanning in memory |
| windows.registry.hivelist | Registry hives in memory |
| windows.hashdump | Extract password hashes |

## Memory Acquisition Formats
| Format | Tool | Extension |
|--------|------|-----------|
| Raw | WinPmem, FTK Imager | .raw, .bin |
| Crash dump | Windows | .dmp |
| VMware | VMware | .vmem |
| LiME | LiME | .lime |
| Hibernation | Windows | hiberfil.sys |

## References
- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [Volatility Plugin Development](https://volatility3.readthedocs.io/en/latest/development.html)
