# API Reference: Detecting Kerberoasting Attacks

## python-evtx Library
```python
from Evtx.Evtx import FileHeader
with open("Security.evtx", "rb") as f:
    fh = FileHeader(f)
    for record in fh.records():
        xml_string = record.xml()
```

## Event ID 4769 - Kerberos TGS Request
```xml
<EventData>
  <Data Name="TargetUserName">svc_sql</Data>
  <Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
  <Data Name="TicketEncryptionType">0x17</Data>
  <Data Name="TicketOptions">0x40810000</Data>
  <Data Name="IpAddress">::ffff:10.0.0.50</Data>
  <Data Name="Status">0x0</Data>
</EventData>
```

## Encryption Type Values
| Hex | Type | Risk |
|-----|------|------|
| 0x17 | RC4-HMAC | Kerberoasting indicator |
| 0x18 | RC4-HMAC-EXP | Kerberoasting indicator |
| 0x11 | AES128-CTS-HMAC-SHA1 | Normal |
| 0x12 | AES256-CTS-HMAC-SHA1 | Normal |

## Detection Logic
1. Filter Event 4769 where TicketEncryptionType = 0x17 (RC4)
2. Exclude machine accounts (ServiceName ending in `$`)
3. Exclude krbtgt service
4. Alert on high-volume TGS from single source (>10 unique SPNs in 5 min)
5. Correlate with Event 4624 for source attribution

## Event ID 4624 - Logon Event (Correlation)
```xml
<Data Name="TargetUserName">attacker_user</Data>
<Data Name="LogonType">3</Data>
<Data Name="IpAddress">10.0.0.50</Data>
<Data Name="WorkstationName">WORKSTATION1</Data>
```

## MITRE ATT&CK Mapping
- T1558.003 - Kerberoasting
- T1558 - Steal or Forge Kerberos Tickets
