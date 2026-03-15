# API Reference: Detecting DCSync Attack in Active Directory

## DCSync Replication GUIDs

| GUID | Right |
|------|-------|
| 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 | DS-Replication-Get-Changes |
| 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 | DS-Replication-Get-Changes-All |
| 89e95b76-444d-4c62-991a-0facbeda640c | DS-Replication-Get-Changes-In-Filtered-Set |

## Windows Event ID 4662 Fields

```xml
<EventID>4662</EventID>
<Data Name="SubjectUserName">attacker</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="Properties">{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}</Data>
<Data Name="ObjectName">DC=corp,DC=local</Data>
```

## python-evtx Usage

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        # Filter for EventID 4662 with replication GUIDs
```

## Splunk SPL Detection Query

```spl
index=wineventlog EventCode=4662
| where Properties IN ("*1131f6aa*", "*1131f6ad*", "*89e95b76*")
| where NOT match(SubjectUserName, ".*\\$$")
| stats count values(Properties) by SubjectUserName Computer
```

## KQL (Microsoft Sentinel)

```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserName !endswith "$"
| project TimeGenerated, SubjectUserName, Computer, Properties
```

## PowerShell - Audit Replication Permissions

```powershell
$domain = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:\$domain"
$acl.Access | Where-Object {
    $_.ObjectType -in @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    )
} | Select IdentityReference, ObjectType
```

## Attack Tools Reference

| Tool | Command |
|------|---------|
| Mimikatz | `lsadump::dcsync /user:krbtgt /domain:corp.local` |
| Impacket | `secretsdump.py corp/admin:pass@dc-ip` |
| DSInternals | `Get-ADReplAccount -SamAccountName krbtgt` |

## CLI Usage

```bash
python agent.py --security-log Security.evtx --dc-accounts known_dcs.txt
python agent.py --generate-sigma
python agent.py --check-perms
```
