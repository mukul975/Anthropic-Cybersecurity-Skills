# API Reference: Detecting Golden Ticket Attacks

## python-evtx Library
```python
from Evtx.Evtx import FileHeader
with open("Security.evtx", "rb") as f:
    fh = FileHeader(f)
    for record in fh.records():
        xml_string = record.xml()
```

## Key Event IDs

### Event 4768 - Kerberos TGT Request (AS-REQ)
```xml
<Data Name="TargetUserName">admin_user</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">15</Data>
<Data Name="IpAddress">::ffff:10.0.0.50</Data>
```

### Event 4624 - Logon Event
```xml
<Data Name="TargetUserName">user</Data>
<Data Name="LogonType">3</Data>
<Data Name="AuthenticationPackageName">Kerberos</Data>
<Data Name="IpAddress">10.0.0.50</Data>
<Data Name="WorkstationName">WKS01</Data>
```

### Event 4672 - Special Privileges Assigned
```xml
<Data Name="SubjectUserName">user</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="PrivilegeList">SeDebugPrivilege SeTcbPrivilege</Data>
```

## Golden Ticket Detection Indicators
| Indicator | Evidence |
|-----------|----------|
| Orphan logon | 4624 Kerberos logon with no 4768 TGT request |
| Privilege anomaly | 4672 admin privs for non-admin account |
| Abnormal TGT lifetime | TGT valid >10 hours (default max) |
| RC4 TGT majority | >50% of TGTs using 0x17 encryption |
| Domain SID mismatch | TGT domain SID differs from DC |

## MITRE ATT&CK
- T1558.001 - Golden Ticket
- T1550 - Use Alternate Authentication Material
