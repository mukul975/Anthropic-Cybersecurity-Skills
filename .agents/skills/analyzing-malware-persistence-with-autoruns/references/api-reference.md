# API Reference: Autoruns Persistence Analysis

## Autoruns CLI (autorunsc.exe)
```cmd
autorunsc.exe -a * -c -h -s -v -vt -o autoruns.csv
```
| Flag | Description |
|------|-------------|
| `-a *` | All autostart categories |
| `-c` | CSV output |
| `-h` | Show file hashes |
| `-s` | Verify digital signatures |
| `-v` | Verify signatures against catalog |
| `-vt` | Check VirusTotal |
| `-o` | Output file |

## CSV Columns
| Column | Description |
|--------|-------------|
| Time | Entry timestamp |
| Entry Location | Registry key or path |
| Entry | Entry name |
| Enabled | enabled/disabled |
| Category | Autoruns category |
| Description | File description |
| Company | Publisher name |
| Image Path | Full binary path |
| Launch String | Complete command line |
| MD5 / SHA-1 / SHA-256 | File hashes |
| Signer | Code signing status |
| VT detection | VirusTotal ratio (e.g., "5/72") |

## Autostart Categories
| Category | Examples |
|----------|---------|
| Logon | Run/RunOnce keys, Startup folder |
| Services | Windows services |
| Drivers | Kernel drivers |
| Scheduled Tasks | Task Scheduler entries |
| Winlogon | Shell, Userinit, Notify |
| WMI | Event subscriptions |
| AppInit | AppInit_DLLs |
| Boot Execute | BootExecute values |
| Image Hijacks | IFEO debugger entries |
| LSA Providers | Authentication packages |

## Suspicious Indicators
| Indicator | Significance |
|-----------|-------------|
| VT detection > 0 | Known malware |
| Unsigned binary | Potential unsigned malware |
| LOLBin in launch string | Living-off-the-land |
| Path in %TEMP% or %PUBLIC% | Staging location |
| Missing company info | Suspicious unsigned entry |

## MITRE ATT&CK Persistence
- T1547.001 - Registry Run Keys / Startup Folder
- T1053.005 - Scheduled Task
- T1543.003 - Windows Service
- T1546.003 - WMI Event Subscription
