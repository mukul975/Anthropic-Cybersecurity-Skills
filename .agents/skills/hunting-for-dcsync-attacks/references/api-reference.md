# DCSync Attack Detection Reference

## Windows Event ID 4662

Directory Service Access event logged when an object in Active Directory is accessed.

### Required Group Policy Configuration

```
Computer Configuration > Policies > Windows Settings > Security Settings >
Advanced Audit Policy Configuration > Audit Policies > DS Access >
Audit Directory Service Access: Success, Failure
```

### Required SACL Configuration

Add "Domain Computers" to the SACL on the domain root object to detect machine account DCSync.

## Key Detection GUIDs

| GUID | Right | Description |
|------|-------|-------------|
| 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 | DS-Replication-Get-Changes | Read replication changes |
| 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 | DS-Replication-Get-Changes-All | Read all replication changes (includes secrets) |
| 89e95b76-444d-4c62-991a-0facbeda640c | DS-Replication-Get-Changes-In-Filtered-Set | Filtered replication set |

### AccessMask Value

`0x100` (256 decimal) = Control Access - logged when access is allowed following extended rights verification.

## Splunk Detection Query

```spl
index=wineventlog EventCode=4662
| where AccessMask="0x100"
| where match(Properties, "(?i)1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") OR match(Properties, "(?i)1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
| where NOT match(SubjectUserName, "\\$$")
| eval is_dc=if(match(SubjectUserName, "(?i)(DC|AZUREADCONNECT)"), "legitimate", "suspicious")
| where is_dc="suspicious"
| stats count by SubjectUserName, SubjectDomainName, Computer, Properties
```

## Elastic KQL Detection

```
event.code: "4662" AND winlog.event_data.AccessMask: "0x100" AND
winlog.event_data.Properties: (*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* OR *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*)
AND NOT winlog.event_data.SubjectUserName: *$
```

## PowerShell Detection

```powershell
# Query Event 4662 for replication GUID access
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4662
} | Where-Object {
    $_.Properties[8].Value -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -and
    $_.Properties[1].Value -notmatch '\$$'
} | Select-Object TimeCreated,
    @{N='Account';E={$_.Properties[1].Value}},
    @{N='Domain';E={$_.Properties[2].Value}}

# List accounts with replication rights
Import-Module ActiveDirectory
(Get-Acl "AD:\DC=domain,DC=local").Access |
    Where-Object { $_.ObjectType -in @(
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    )} | Select-Object IdentityReference, ActiveDirectoryRights
```

## Attack Tools (for Detection Signatures)

```bash
# Mimikatz DCSync
lsadump::dcsync /domain:corp.local /user:krbtgt

# Impacket secretsdump.py
secretsdump.py -just-dc corp.local/admin:Password@dc01.corp.local

# Impacket - specific user
secretsdump.py -just-dc-user krbtgt corp.local/admin:Password@dc01.corp.local
```

## MITRE ATT&CK Mapping

- **Technique**: T1003.006 - OS Credential Dumping: DCSync
- **Tactic**: Credential Access
- **Platforms**: Windows
- **Data Sources**: Active Directory: Active Directory Object Access, Network Traffic

## Response Checklist

1. Disable compromised account immediately
2. Reset krbtgt password twice (12-hour interval between resets)
3. Revoke all Kerberos tickets (purge ticket cache)
4. Audit all accounts with replication rights on domain object
5. Review source host for additional compromise indicators
6. Check for persistence mechanisms (scheduled tasks, services, WMI)
