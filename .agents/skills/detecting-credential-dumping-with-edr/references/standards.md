# Standards and References - Credential Dumping Detection

## MITRE ATT&CK Mappings

### T1003 - OS Credential Dumping (Parent Technique)

| Sub-Technique | Name | Description |
|---------------|------|-------------|
| T1003.001 | LSASS Memory | Dumping credentials stored in LSASS process memory |
| T1003.002 | Security Account Manager | Extracting local hashes from SAM database |
| T1003.003 | NTDS | Stealing AD database from Domain Controllers |
| T1003.004 | LSA Secrets | Accessing stored service account credentials |
| T1003.005 | Cached Domain Credentials | Extracting DCC2 hashed credentials |
| T1003.006 | DCSync | Simulating DC replication to extract credentials |
| T1003.007 | Proc Filesystem (/proc) | Linux credential extraction |
| T1003.008 | /etc/passwd and /etc/shadow | Unix credential files |

### Related Techniques
- **T1555 - Credentials from Password Stores**: Browser, keychain, password manager credentials
- **T1552 - Unsecured Credentials**: Files, registry, bash history, cloud metadata
- **T1558 - Steal or Forge Kerberos Tickets**: Kerberoasting, Golden/Silver tickets
- **T1550 - Use Alternate Authentication Material**: Pass the Hash, Pass the Ticket

### Tactic
- **TA0006 - Credential Access**

## Detection Data Sources

### LSASS Access Detection
| Source | Event ID | Details |
|--------|----------|---------|
| Sysmon | 10 | ProcessAccess - TargetImage = lsass.exe |
| Windows Security | 4656 | Handle requested to process object |
| Windows Security | 4663 | Attempt to access process object |
| Windows Security | 4688 | Process creation with command line |
| ETW | Microsoft-Windows-Kernel-Process | Kernel-level process access |

### SAM/Registry Detection
| Source | Event ID | Details |
|--------|----------|---------|
| Sysmon | 1 | reg.exe with save SAM/SECURITY/SYSTEM |
| Windows Security | 4656 | Handle to registry key |
| Windows Security | 4688 | reg.exe/regedit.exe command line |

### DCSync Detection
| Source | Event ID | Details |
|--------|----------|---------|
| Windows Security | 4662 | DS-Replication-Get-Changes operation |
| Windows Security | 4624/4625 | Authentication to DC from non-DC source |
| Network | DRSUAPI | RPC calls for directory replication |

### NTDS Access Detection
| Source | Event ID | Details |
|--------|----------|---------|
| Sysmon | 1 | ntdsutil.exe, vssadmin.exe execution |
| Windows Security | 4688 | Shadow copy creation commands |
| VSS | 8224 | Volume Shadow Copy Service operations |

## LSASS Access Mask Reference

| Access Mask | Hex | Meaning |
|-------------|-----|---------|
| PROCESS_VM_READ | 0x0010 | Read process memory |
| PROCESS_QUERY_INFORMATION | 0x0400 | Query process info |
| 0x1010 | Combined | VM_READ + QUERY_INFO (Mimikatz default) |
| 0x1038 | Combined | Common credential dumping mask |
| 0x1FFFFF | PROCESS_ALL_ACCESS | Full access to process |
| 0x0410 | Combined | Query + VM_READ minimal |

## Known Credential Dumping Tools

| Tool | Technique | Detection Signature |
|------|-----------|-------------------|
| Mimikatz | T1003.001, T1003.006 | LSASS access with 0x1010, sekurlsa module |
| LaZagne | T1003.001, T1555 | Multi-credential extractor |
| ProcDump | T1003.001 | Signed MS tool, -ma lsass.exe |
| comsvcs.dll | T1003.001 | MiniDump via rundll32 |
| secretsdump.py | T1003.002, T1003.003, T1003.006 | Impacket DCSync/SAM |
| ntdsutil.exe | T1003.003 | IFM creation for NTDS |
| SharpDump | T1003.001 | .NET LSASS dumper |
| PPLdump | T1003.001 | PPL bypass LSASS dump |
| nanodump | T1003.001 | Stealthy minidump |

## Regulatory References
- NIST SP 800-171 Rev 2: 3.1.1 (Access Control)
- CIS Controls v8: Control 6 (Access Control Management)
- PCI DSS 4.0: Requirement 7 (Restrict Access)
