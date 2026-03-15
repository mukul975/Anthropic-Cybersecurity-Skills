# API Reference: Analyzing Windows Prefetch with Python

## windowsprefetch Library

```python
import windowsprefetch

pf = windowsprefetch.Prefetch("CMD.EXE-1234ABCD.pf")
print(pf.executableName)  # CMD.EXE
print(pf.runCount)        # 42
print(pf.lastRunTime)     # 2025-01-15 10:30:22
print(pf.timestamps)      # List of up to 8 execution times
print(pf.resources)       # List of loaded files/DLLs
print(pf.volumes)         # Volume info (name, serial, creation)
```

Install: `pip install windowsprefetch`

## Prefetch File Versions

| Version | Windows | Max Timestamps |
|---------|---------|----------------|
| 17 | XP/2003 | 1 |
| 23 | Vista/7 | 1 |
| 26 | 8/8.1 | 8 |
| 30 | 10/11 | 8 (compressed) |

## File Naming Convention

Format: `EXECUTABLE-XXXXXXXX.pf`
- EXECUTABLE: uppercase executable name
- XXXXXXXX: hash of file path (allows multiple entries per executable)

## Suspicious Executables to Flag

| Category | Examples |
|----------|---------|
| Credential tools | mimikatz, rubeus, lazagne, secretsdump |
| Lateral movement | psexec, psexesvc, wmiexec |
| C2 agents | beacon, meterpreter, covenant, empire |
| LOLBins | certutil, mshta, regsvr32, rundll32, bitsadmin |
| Recon | sharphound, bloodhound, nmap |

## Prefetch Directory Location

```
C:\Windows\Prefetch\
```

Requires admin privileges to read. Enable via:
```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
```

## References

- windowsprefetch PyPI: https://pypi.org/project/windowsprefetch/
- Windows Prefetch Parser: https://github.com/PoorBillionaire/Windows-Prefetch-Parser
- libscca/pyscca: https://github.com/libyal/libscca
- SANS Prefetch Analysis: https://www.sans.org/blog/a-prescription-for-windows-prefetch-analysis
