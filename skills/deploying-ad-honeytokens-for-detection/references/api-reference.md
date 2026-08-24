# API Reference and PowerShell Commands

## Active Directory Honeytoken Management

### Create Honeytoken User Account
```powershell
# Basic honeytoken creation
New-ADUser -Name "svc-backup-sql" `
           -SamAccountName "svc-backup-sql" `
           -UserPrincipalName "svc-backup-sql@corp.local" `
           -Description "SQL Server backup service account" `
           -Enabled $true `
           -PasswordNeverExpires $true `
           -CannotChangePassword $true `
           -AccountPassword (ConvertTo-SecureString "P@ssw0rd$(Get-Random -Minimum 1000 -Maximum 9999)!" -AsPlainText -Force) `
           -Path "OU=Service Accounts,DC=corp,DC=local"

# Verify creation
Get-ADUser -Identity "svc-backup-sql" -Properties *
```

### Configure Service Principal Name (SPN)
```powershell
# Set SPN (makes account Kerberoastable)
Set-ADUser -Identity "svc-backup-sql" -ServicePrincipalNames @{Add="MSSQLSvc/sql-backup.corp.local:1433"}

# Verify SPN
Get-ADUser -Identity "svc-backup-sql" -Properties ServicePrincipalNames | Select -ExpandProperty ServicePrincipalNames

# List all accounts with SPNs (including honeytokens)
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalNames | Select SamAccountName, ServicePrincipalNames
```

### Add to High-Privilege Groups
```powershell
# Add honeytoken to Domain Admins (NEVER use legitimately)
Add-ADGroupMember -Identity "Domain Admins" -Members "svc-backup-sql"

# Verify membership
Get-ADGroupMember -Identity "Domain Admins" | Where-Object {$_.SamAccountName -eq "svc-backup-sql"}

# Add to multiple groups
$Groups = @("Domain Admins", "Schema Admins", "Backup Operators")
foreach ($Group in $Groups) {
    Add-ADGroupMember -Identity $Group -Members "svc-backup-sql"
    Write-Host "Added to $Group"
}
```

### Set ACL Honeypot (Fake Permissions)
```powershell
# Grant honeytoken GenericAll on Domain Admins group
$Identity = Get-ADUser "svc-backup-sql"
$Target = Get-ADGroup "Domain Admins"

$ACL = Get-ACL "AD:$($Target.DistinguishedName)"
$SID = [System.Security.Principal.SecurityIdentifier]$Identity.SID

$Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $SID,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$ACL.AddAccessRule($Rule)
Set-ACL -Path "AD:$($Target.DistinguishedName)" -AclObject $ACL

Write-Host "✓ Honeytoken has GenericAll on Domain Admins (BloodHound will show this)"
```

### Batch Deployment Script
```powershell
# deploy_honeytokens.ps1
# Deploys multiple honeytokens with varying characteristics

param(
    [string]$Domain = "corp.local",
    [string]$OUPath = "OU=Service Accounts,DC=corp,DC=local"
)

$Honeytokens = @(
    @{
        Name = "svc-sql-backup"
        SPN = "MSSQLSvc/sql-backup.corp.local:1433"
        Description = "SQL Server backup service account - DO NOT MODIFY"
        Groups = @("Backup Operators")
    },
    @{
        Name = "svc-vmware-mgmt"
        SPN = "HTTP/vmware-mgmt.corp.local"
        Description = "VMware vCenter management service"
        Groups = @("Domain Admins")
    },
    @{
        Name = "svc-backup-exec"
        SPN = "BackupExec/backup.corp.local"
        Description = "Backup Exec enterprise backup service"
        Groups = @("Backup Operators")
    },
    @{
        Name = "adm-helpdesk-t2"
        SPN = $null
        Description = "Tier 2 helpdesk administrator account"
        Groups = @("Account Operators")
    },
    @{
        Name = "sqlserver-readonly"
        SPN = "MSSQLSvc/sqlserver-ro.corp.local:1433"
        Description = "SQL Server read-only reporting service"
        Groups = @()
    }
)

Write-Host "Deploying honeytokens..." -ForegroundColor Cyan
Write-Host "Domain: $Domain" -ForegroundColor Cyan
Write-Host "OU Path: $OUPath`n" -ForegroundColor Cyan

$DeployedCount = 0

foreach ($Token in $Honeytokens) {
    try {
        Write-Host "[*] Creating: $($Token.Name)"
        
        # Generate secure random password
        $Password = "Honeytoken$(Get-Random -Minimum 10000 -Maximum 99999)!@#"
        
        # Create user
        New-ADUser -Name $Token.Name `
                   -SamAccountName $Token.Name `
                   -UserPrincipalName "$($Token.Name)@$Domain" `
                   -Description $Token.Description `
                   -Enabled $true `
                   -PasswordNeverExpires $true `
                   -CannotChangePassword $true `
                   -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
                   -Path $OUPath `
                   -ErrorAction Stop
        
        Write-Host "    ✓ User created" -ForegroundColor Green
        
        # Set SPN if specified
        if ($Token.SPN) {
            Set-ADUser -Identity $Token.Name -ServicePrincipalNames @{Add=$Token.SPN}
            Write-Host "    ✓ SPN configured: $($Token.SPN)" -ForegroundColor Green
        }
        
        # Add to groups
        foreach ($Group in $Token.Groups) {
            Add-ADGroupMember -Identity $Group -Members $Token.Name -ErrorAction SilentlyContinue
            Write-Host "    ✓ Added to group: $Group" -ForegroundColor Green
        }
        
        $DeployedCount++
        Write-Host ""
        
    } catch {
        Write-Host "    ✗ Error: $_" -ForegroundColor Red
        Write-Host ""
    }
}

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "Successfully deployed: $DeployedCount/$($Honeytokens.Count) honeytokens" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
```

### Remove/Cleanup Honeytokens
```powershell
# Remove single honeytoken
Remove-ADUser -Identity "svc-backup-sql" -Confirm:$false

# Batch removal (use with caution)
$HoneytokenNames = @("svc-backup-sql", "svc-vmware-mgmt", "svc-backup-exec", "adm-helpdesk-t2", "sqlserver-readonly")

foreach ($Name in $HoneytokenNames) {
    Remove-ADUser -Identity $Name -Confirm:$false
    Write-Host "Removed: $Name"
}
```

## SIEM Query Templates

### Splunk SPL Queries

#### Kerberoasting Detection (Event 4769)
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4769
(ServiceName="MSSQLSvc/sql-backup.corp.local:1433" OR 
 ServiceName="HTTP/vmware-mgmt.corp.local" OR 
 ServiceName="MSSQLSvc/sqlserver-ro.corp.local:1433")
| eval severity="critical"
| eval attack_type="Kerberoasting"
| eval is_rc4=if(TicketEncryptionType="0x17", "YES", "NO")
| table _time, ServiceName, IpAddress, Workstation, TicketEncryptionType, is_rc4
| where is_rc4="YES"
```

#### TGT Request Monitoring (Event 4768)
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4768
(TargetUserName="svc-backup-sql" OR 
 TargetUserName="svc-vmware-mgmt" OR 
 TargetUserName="adm-helpdesk-t2")
| stats count by _time, TargetUserName, IpAddress, Workstation
| where count > 0
| eval alert="Honeytoken TGT Request"
```

#### NTLM Authentication (Event 4776)
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4776
(TargetUserName="svc-backup-sql" OR 
 TargetUserName="svc-vmware-mgmt" OR 
 TargetUserName="adm-helpdesk-t2")
| eval alert_type="Honeytoken NTLM Authentication"
| table _time, TargetUserName, Workstation, Status
```

#### Successful Logon (Event 4624 - Critical)
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4624
(TargetUserName="svc-backup-sql" OR 
 TargetUserName="svc-vmware-mgmt" OR 
 TargetUserName="adm-helpdesk-t2")
| eval severity="CRITICAL"
| eval alert="HONEYTOKEN SUCCESSFUL LOGON - IMMEDIATE RESPONSE REQUIRED"
| table _time, TargetUserName, LogonType, IpAddress, WorkstationName, ProcessName
```

#### DCSync Detection (Event 4662)
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4662
ObjectType="domain"
(Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR 
 Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
(SubjectUserName="svc-backup-sql" OR 
 SubjectUserName="svc-vmware-mgmt")
| eval attack="DCSync Attempt via Honeytoken"
| table _time, SubjectUserName, ObjectName, Properties, Computer
```

---

### Microsoft Sentinel (KQL) Queries

#### Kerberoasting Detection
```kql
SecurityEvent
| where EventID == 4769
| where ServiceName in ("MSSQLSvc/sql-backup.corp.local:1433", 
                       "HTTP/vmware-mgmt.corp.local", 
                       "MSSQLSvc/sqlserver-ro.corp.local:1433")
| extend IsRC4 = iff(TicketEncryptionType == "0x17", true, false)
| where IsRC4 == true
| extend AlertTitle = strcat("🚨 Kerberoasting Detected: ", ServiceName)
| project TimeGenerated, ServiceName, IpAddress, WorkstationName, TicketEncryptionType
```

#### Honeytoken Authentication (All Events)
```kql
let HoneytokenAccounts = dynamic(["svc-backup-sql", "svc-vmware-mgmt", "adm-helpdesk-t2", "sqlserver-readonly"]);
SecurityEvent
| where EventID in (4768, 4769, 4776, 4624, 4625)
| where TargetUserName in (HoneytokenAccounts)
| extend Severity = "High"
| extend AlertType = case(
    EventID == 4769, "Kerberoasting (TGS Request)",
    EventID == 4768, "TGT Request",
    EventID == 4776, "NTLM Authentication",
    EventID == 4624, "Successful Logon",
    EventID == 4625, "Failed Logon",
    "Unknown"
)
| project TimeGenerated, EventID, AlertType, TargetUserName, IpAddress, WorkstationName
```

#### DCSync Detection
```kql
SecurityEvent
| where EventID == 4662
| where ObjectType == "domain"
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
| where SubjectUserName in ("svc-backup-sql", "svc-vmware-mgmt", "adm-helpdesk-t2")
| extend AlertTitle = "🚨 DCSync Attack via Honeytoken"
| project TimeGenerated, SubjectUserName, ObjectName, Properties, Computer
```

---

### Elasticsearch / ELK Query (DSL)
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "terms": {
            "event.code": ["4768", "4769", "4776", "4624"]
          }
        },
        {
          "terms": {
            "winlog.event_data.TargetUserName.keyword": [
              "svc-backup-sql",
              "svc-vmware-mgmt",
              "adm-helpdesk-t2",
              "sqlserver-readonly"
            ]
          }
        }
      ]
    }
  },
  "aggs": {
    "by_event": {
      "terms": {
        "field": "event.code"
      }
    },
    "by_user": {
      "terms": {
        "field": "winlog.event_data.TargetUserName.keyword"
      }
    }
  }
}
```

## Testing and Validation

### Test Kerberoasting (Rubeus)
```powershell
# Download Rubeus from https://github.com/GhostPack/Rubeus
.\Rubeus.exe kerberoast /user:svc-backup-sql /nowrap

# Expected output:
# [*] SamAccountName         : svc-backup-sql
# [*] DistinguishedName      : CN=svc-backup-sql,OU=Service Accounts,DC=corp,DC=local
# [*] ServicePrincipalName   : MSSQLSvc/sql-backup.corp.local:1433
# [*] Hash                   : $krb5tgs$23$*svc-backup-sql$...

# Expected Alert: Event 4769 for MSSQLSvc/sql-backup.corp.local:1433
```

### Test Kerberoasting (Impacket GetUserSPNs.py)
```bash
# From Kali Linux
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
  -request -dc-ip 10.0.1.5 corp.local/testuser:password

# Expected output shows honeytoken SPNs:
# ServicePrincipalName                     Name             MemberOf
# ---------------------------------------  ---------------  --------
# MSSQLSvc/sql-backup.corp.local:1433      svc-backup-sql   CN=Domain Admins...
# HTTP/vmware-mgmt.corp.local              svc-vmware-mgmt  CN=Domain Admins...

# Extract TGS ticket for offline cracking
python3 GetUserSPNs.py -request -dc-ip 10.0.1.5 corp.local/testuser:password -outputfile tgs_tickets.txt
```

### Test Authentication
```powershell
# Test NTLM authentication
$cred = Get-Credential -UserName "corp\svc-backup-sql"
# Enter honeytoken password

Test-Connection -ComputerName dc01.corp.local -Credential $cred

# Expected Alert: Event 4776 (NTLM auth) or 4768 (Kerberos TGT)
```

### Test BloodHound Enumeration
```powershell
# Run SharpHound collector
.\SharpHound.exe -c All --zipfilename bloodhound_test.zip

# Import into BloodHound and query:
# "Shortest Path to Domain Admins from svc-backup-sql"
# "Find all Kerberoastable Users"

# Expected: Honeytoken accounts visible in graph with paths to high-value targets
```

## Monitoring and Alerting Automation

### Splunk Alert Action (Email)
```xml
<!-- savedsearches.conf -->
[Honeytoken Access Alert]
search = index=wineventlog sourcetype=WinEventLog:Security (EventCode=4768 OR EventCode=4769) (TargetUserName="svc-backup-sql" OR TargetUserName="svc-vmware-mgmt")
cron_schedule = */5 * * * *
enableSched = 1
action.email = 1
action.email.to = security-team@corp.local
action.email.subject = 🚨 CRITICAL: Honeytoken Access Detected
action.email.message.alert = Honeytoken account accessed. Immediate investigation required.
alert.severity = 5
alert.priority = critical
```

### Splunk Webhook to Slack
```python
# slack_webhook.py (Splunk alert action)
import requests
import json

SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

def send_alert(user, event_id, ip_address):
    message = {
        "text": "🚨 *CRITICAL ALERT: Honeytoken Access*",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 Honeytoken Access Detected"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*User:*\n{user}"},
                    {"type": "mrkdwn", "text": f"*Event ID:*\n{event_id}"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{ip_address}"},
                    {"type": "mrkdwn", "text": "*Severity:*\nCRITICAL"}
                ]
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View in Splunk"},
                        "url": "https://splunk.corp.local/app/search"
                    }
                ]
            }
        ]
    }
    
    requests.post(SLACK_WEBHOOK, json=message)

# Usage:
send_alert("svc-backup-sql", "4769", "10.2.45.78")
```

### Microsoft Sentinel Playbook (Logic App)
```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "actions": {
      "Send_Email": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['office365']['connectionId']"
            }
          },
          "method": "post",
          "body": {
            "To": "security-team@corp.com",
            "Subject": "🚨 Honeytoken Access Alert",
            "Body": "Honeytoken @{triggerBody()?['TargetUserName']} accessed from @{triggerBody()?['IpAddress']}"
          },
          "path": "/v2/Mail"
        }
      },
      "Create_Incident": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuresentinel']['connectionId']"
            }
          },
          "method": "put",
          "body": {
            "properties": {
              "title": "Honeytoken Access Detected",
              "severity": "High",
              "status": "New"
            }
          }
        }
      }
    },
    "triggers": {
      "Microsoft_Sentinel_alert": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuresentinel']['connectionId']"
            }
          }
        }
      }
    }
  }
}
```

## Maintenance and Audit

### List All Honeytokens
```powershell
# Query all users with "honeytoken" in description or specific naming pattern
Get-ADUser -Filter {Description -like "*honeytoken*" -or SamAccountName -like "svc-*"} -Properties Description, ServicePrincipalNames, MemberOf | 
  Select SamAccountName, Description, ServicePrincipalNames, @{N='Groups';E={$_.MemberOf -join '; '}}
```

### Verify Honeytoken Configuration
```powershell
# verify_honeytokens.ps1
$HoneytokenNames = @("svc-backup-sql", "svc-vmware-mgmt", "adm-helpdesk-t2")

foreach ($Name in $HoneytokenNames) {
    $User = Get-ADUser -Identity $Name -Properties Enabled, PasswordNeverExpires, ServicePrincipalNames, MemberOf -ErrorAction SilentlyContinue
    
    if ($User) {
        Write-Host "[✓] $Name exists" -ForegroundColor Green
        Write-Host "    Enabled: $($User.Enabled)"
        Write-Host "    PasswordNeverExpires: $($User.PasswordNeverExpires)"
        Write-Host "    SPNs: $($User.ServicePrincipalNames -join ', ')"
        Write-Host "    Groups: $($User.MemberOf.Count)"
    } else {
        Write-Host "[✗] $Name MISSING" -ForegroundColor Red
    }
}
```

### Monthly Audit Report
```powershell
# Generate monthly audit report
$Report = @()

$Honeytokens = Get-ADUser -Filter {Description -like "*honeytoken*"} -Properties LastLogonDate, PasswordLastSet, ServicePrincipalNames

foreach ($Token in $Honeytokens) {
    $Report += [PSCustomObject]@{
        Name = $Token.SamAccountName
        LastLogon = $Token.LastLogonDate
        PasswordAge = (New-TimeSpan -Start $Token.PasswordLastSet -End (Get-Date)).Days
        SPNs = $Token.ServicePrincipalNames -join '; '
        Status = if ($Token.LastLogonDate) { "⚠️ LOGGED IN" } else { "✓ Never Used" }
    }
}

$Report | Export-Csv -Path "C:\Reports\Honeytoken_Audit_$(Get-Date -Format 'yyyy-MM').csv" -NoTypeInformation
$Report | Format-Table -AutoSize
```

## References

- Active Directory PowerShell Module: https://docs.microsoft.com/powershell/module/activedirectory/
- Windows Security Event Log Reference: https://docs.microsoft.com/windows/security/threat-protection/auditing/
- Splunk SPL Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/
- Microsoft Sentinel KQL: https://docs.microsoft.com/azure/data-explorer/kusto/query/
- Rubeus: https://github.com/GhostPack/Rubeus
- Impacket: https://github.com/fortra/impacket
