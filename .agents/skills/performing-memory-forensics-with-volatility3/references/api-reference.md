# API Reference: Memory Forensics with Volatility 3

## Volatility 3 CLI

| Plugin | Description |
|--------|-------------|
| `windows.info` | OS version, kernel base, system time |
| `windows.pslist` | List processes via EPROCESS linked list |
| `windows.pstree` | Process tree with parent-child relationships |
| `windows.psscan` | Pool scan for processes (finds hidden) |
| `windows.malfind` | Detect injected code in process memory |
| `windows.netscan` | Active network connections and listening ports |
| `windows.cmdline` | Command line arguments for all processes |
| `windows.dlllist` | DLLs loaded per process |
| `windows.hashdump` | Extract cached NTLM password hashes |
| `windows.lsadump` | LSA secrets from memory |
| `windows.svcscan` | Windows services enumeration |
| `windows.modules` | Loaded kernel modules |
| `windows.modscan` | Pool scan for kernel modules (finds hidden) |
| `windows.registry.hivelist` | List registry hives in memory |
| `windows.registry.printkey` | Print specific registry key values |
| `yarascan` | Scan memory with YARA rules |
| `windows.memmap` | Dump process memory to disk |

## Common Flags

| Flag | Description |
|------|-------------|
| `-f <file>` | Memory dump file path |
| `--pid <pid>` | Filter by process ID |
| `--dump` | Dump matched content to files |
| `-o <dir>` | Output directory for dumps |
| `--yara-file <file>` | YARA rules file for scanning |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute Volatility 3 CLI commands |
| `re` | stdlib | Parse plugin output |

## References

- Volatility 3: https://github.com/volatilityfoundation/volatility3
- Symbol tables: https://downloads.volatilityfoundation.org/volatility3/symbols/
- LiME: https://github.com/504ensicsLabs/LiME
- MemProcFS: https://github.com/ufrisk/MemProcFS
