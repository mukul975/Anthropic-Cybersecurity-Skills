# Windows Event Logging for Detection — API Reference

## Key PowerShell Cmdlets

| Cmdlet | Description |
|--------|-------------|
| `auditpol /get /category:*` | View advanced audit policy |
| `auditpol /set /subcategory:"Process Creation" /success:enable` | Enable audit subcategory |
| `Get-WinEvent -ListLog *` | List available event logs |
| `wevtutil sl Security /ms:1073741824` | Set Security log max size to 1 GB |

## Critical Event IDs for Detection

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624/4625 | Security | Successful/failed logon |
| 4662 | Security | Directory service object access |
| 4688 | Security | Process creation (with command line) |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4732 | Security | Member added to security group |
| 4768/4769 | Security | Kerberos TGT/service ticket |
| 1 | Sysmon | Process creation with hashes |
| 3 | Sysmon | Network connection |
| 7 | Sysmon | Image loaded (DLL) |
| 11 | Sysmon | File creation |
| 4104 | PowerShell | Script block logging |

## Recommended Log Sizes

| Log | Minimum Size |
|-----|-------------|
| Security | 1 GB |
| Sysmon/Operational | 512 MB |
| PowerShell/Operational | 256 MB |
| System | 256 MB |

## External References

- [Microsoft Audit Policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/)
