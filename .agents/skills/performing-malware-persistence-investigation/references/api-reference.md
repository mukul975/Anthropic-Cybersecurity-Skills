# API Reference: Malware Persistence Investigation

## python-registry Library

```python
from Registry import Registry
reg = Registry.Registry("SOFTWARE")
key = reg.open("Microsoft\\Windows\\CurrentVersion\\Run")
for value in key.values():
    print(f"{value.name()} -> {value.value()}")
```

## Key Windows Persistence Locations

| Location | Type | Registry Path / Filesystem Path |
|----------|------|-------------------------------|
| Run Keys (HKLM) | Registry | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| Run Keys (HKCU) | Registry | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run` |
| Services | Registry | `SYSTEM\ControlSetXXX\Services` |
| Scheduled Tasks | Filesystem | `C:\Windows\System32\Tasks\` |
| WMI Subscriptions | WMI DB | `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` |
| Startup Folder | Filesystem | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |
| COM Hijacking | Registry | `SOFTWARE\Classes\CLSID\{...}\InprocServer32` |

## Linux Persistence Locations

| Location | Mechanism |
|----------|-----------|
| `/etc/crontab`, `/etc/cron.d/` | Cron jobs |
| `/etc/systemd/system/*.service` | Systemd services |
| `~/.ssh/authorized_keys` | SSH key persistence |
| `/etc/rc.local` | Boot scripts |
| `/etc/ld.so.preload` | Shared library injection |
| `/etc/pam.d/` | PAM backdoors |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `python-registry` | >=1.4 | Offline Windows registry hive parsing |
| `xml.etree.ElementTree` | stdlib | Scheduled task XML parsing |
| `pathlib` | stdlib | Filesystem traversal |

## References

- Autoruns: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- RegRipper: https://github.com/keydet89/RegRipper3.0
- PersistenceSniper: https://github.com/last-byte/PersistenceSniper
- MITRE ATT&CK Persistence: https://attack.mitre.org/tactics/TA0003/
