# Detailed Hunting Workflow - DCSync Attack Detection

## Phase 1: Enumerate Legitimate Replication Accounts

### Step 1.1 - List All Domain Controllers
```powershell
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem
```

### Step 1.2 - Find Accounts with Replication Rights
```powershell
# Find all accounts with Replicating Directory Changes
Import-Module ActiveDirectory
$rootDSE = Get-ADRootDSE
$domainDN = $rootDSE.defaultNamingContext
$acl = Get-Acl "AD:\$domainDN"
$acl.Access | Where-Object {
    $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or
    $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
} | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
```

### Step 1.3 - BloodHound Query for DCSync Rights
```cypher
MATCH p=(n)-[:GetChanges|GetChangesAll]->(d:Domain)
WHERE NOT n:Domain
RETURN n.name, labels(n)
```

## Phase 2: Deploy Detection

### Step 2.1 - Enable Required Audit Policy
```cmd
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

### Step 2.2 - Configure SACL on Domain Object
Apply SACL to the domain root object monitoring for:
- Control Access rights
- Access to Replication GUIDs
- By Everyone or Authenticated Users

## Phase 3: Active Monitoring

### Step 3.1 - Splunk Real-Time Detection
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4662
| rex field=Properties "(?<guid>\{[0-9a-f-]+\})"
| where guid IN ("{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
    "{89e95b76-444d-4c62-991a-0facbeda640c}")
| lookup dc_accounts SubjectUserName OUTPUT is_dc
| where is_dc!="true"
| eval alert_severity="CRITICAL"
| table _time SubjectUserName SubjectDomainName Computer guid alert_severity
```

### Step 3.2 - Network-Level Detection
```spl
index=zeek sourcetype=dce_rpc
| where operation="DRSGetNCChanges"
| lookup domain_controllers src_ip OUTPUT is_dc
| where is_dc!="true"
| table _time src_ip dst_ip operation
```

## Phase 4: Investigation

### Step 4.1 - Determine Source Machine
Correlate Event 4662 with Event 4624 to identify the source workstation:
```spl
index=wineventlog EventCode=4624 LogonType=3
| where TargetUserName=[suspected_account]
| table _time TargetUserName IpAddress WorkstationName LogonType
```

### Step 4.2 - Check for Subsequent Credential Abuse
```spl
index=wineventlog EventCode=4769
| where ServiceName="krbtgt"
| where TicketEncryptionType="0x17"
| table _time TargetUserName ServiceName IpAddress TicketEncryptionType
```

## Phase 5: Response

### Step 5.1 - Immediate Containment
1. Disable compromised account immediately
2. Rotate KRBTGT password (twice, 12 hours apart)
3. Reset all service account passwords
4. Block source IP at network level
5. Isolate source machine for forensics

### Step 5.2 - Remediation
1. Remove unauthorized replication rights
2. Review all accounts with DCSync-capable permissions
3. Implement tiered administration model
4. Enable Microsoft Defender for Identity DCSync alerts
5. Deploy Protected Users security group for admin accounts
