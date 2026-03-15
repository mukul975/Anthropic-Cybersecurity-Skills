# API Reference: Analyzing Windows Event Logs in Splunk

## splunk-sdk Connection

```python
import splunklib.client as client
service = client.connect(host="splunk", port=8089, username="admin", password="pass")
```

## Key Windows Security Event IDs

| EventCode | Description | ATT&CK Technique |
|-----------|-------------|-------------------|
| 4624 | Successful logon | T1078 |
| 4625 | Failed logon | T1110 |
| 4648 | Explicit credential logon | T1078 |
| 4672 | Special privileges assigned | T1134 |
| 4688 | New process created | T1059 |
| 4698 | Scheduled task created | T1053.005 |
| 4720 | User account created | T1136.001 |
| 4732 | Member added to security group | T1098 |
| 4768 | Kerberos TGT requested | T1558 |
| 4769 | Kerberos service ticket | T1558.003 |

## Key Sysmon Event IDs

| EventCode | Description |
|-----------|-------------|
| 1 | Process creation (full command line, hashes) |
| 3 | Network connection |
| 7 | Image loaded (DLL) |
| 10 | Process access (LSASS credential dumping) |
| 11 | File creation |
| 13 | Registry value set |
| 22 | DNS query |

## Logon Types

| Type | Description | Context |
|------|-------------|---------|
| 2 | Interactive | Local console logon |
| 3 | Network | SMB, WMI, PowerShell Remoting |
| 7 | Unlock | Workstation unlock |
| 9 | NewCredentials | runas /netonly |
| 10 | RemoteInteractive | RDP logon |

## SPL Detection Patterns

```spl
# Brute force detection
index=wineventlog EventCode=4625 | stats count by src_ip | where count > 20

# Kerberoasting (T1558.003)
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| where ServiceName != "krbtgt"

# DCSync detection (T1003.006)
index=wineventlog EventCode=4662
| where ObjectType="*domainDNS*"
| search Properties="*Replicating Directory Changes*"
```

### References

- splunk-sdk: https://pypi.org/project/splunk-sdk/
- Splunk CIM: https://docs.splunk.com/Documentation/CIM/latest/User/Overview
- Windows Security Log Encyclopedia: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
