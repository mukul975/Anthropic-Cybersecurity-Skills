# SIEM Detection Rules for Active Directory Honeytokens

This document provides copy-paste ready detection rules for major SIEM platforms.

## Configuration Checklist

Before deploying rules, ensure:
- [ ] Windows Security Event Logs forwarded to SIEM (Event IDs: 4768, 4769, 4776, 4624, 4625, 4662)
- [ ] Domain Controllers configured with appropriate audit policies
- [ ] Honeytoken account list documented (update `HoneytokenAccounts` variable in rules)
- [ ] Alert severity configured (recommend: CRITICAL)
- [ ] Alert destinations configured (email, Slack, PagerDuty, ServiceNow)
- [ ] SOC runbook created for honeytoken alert response

---

## Splunk Enterprise Security

### Rule 1: Kerberoasting Detection (Event 4769)

**Detection Logic**: TGS request for honeytoken SPN with RC4 encryption

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4769
[| makeresults 
 | eval HoneytokenSPNs="MSSQLSvc/sql-backup.corp.local:1433,HTTP/vmware-mgmt.corp.local,MSSQLSvc/sqlserver-ro.corp.local:1433,BackupExec/backup.corp.local" 
 | makemv delim="," HoneytokenSPNs 
 | mvexpand HoneytokenSPNs 
 | rename HoneytokenSPNs as ServiceName 
 | fields ServiceName]
| eval is_rc4=if(TicketEncryptionType="0x17", "YES", "NO")
| eval severity="CRITICAL"
| eval attack_type="Kerberoasting"
| eval alert_title="🚨 Kerberoasting Attack Detected - Honeytoken SPN Requested"
| table _time, ServiceName, IpAddress, WorkstationName, TicketEncryptionType, is_rc4, Computer
| where is_rc4="YES"
```

**Alert Configuration** (savedsearches.conf):
```ini
[Honeytoken - Kerberoasting Detection]
search = <paste above SPL>
cron_schedule = */2 * * * *
enableSched = 1
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert.severity = 5
alert.priority = critical
action.email = 1
action.email.to = soc-team@corp.local
action.email.subject = 🚨 CRITICAL: Kerberoasting Attack on Honeytoken
alert.digest_mode = 0
```

---

### Rule 2: TGT Request Monitoring (Event 4768)

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4768
(TargetUserName="svc-sql-backup" OR TargetUserName="svc-vmware-mgmt" OR TargetUserName="adm-helpdesk-t2" OR TargetUserName="sqlserver-readonly" OR TargetUserName="svc-backup-exec")
| eval severity="HIGH"
| eval alert_type="Honeytoken TGT Request"
| eval alert_message="Honeytoken account " . TargetUserName . " requested TGT from " . IpAddress
| table _time, TargetUserName, IpAddress, WorkstationName, TicketOptions, PreAuthType, Computer
| eval recommendation="Investigate source workstation immediately"
```

---

### Rule 3: Successful Logon - CRITICAL (Event 4624)

**Note**: Honeytokens should NEVER log in; any 4624 event = confirmed compromise

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4624
(TargetUserName="svc-sql-backup" OR TargetUserName="svc-vmware-mgmt" OR TargetUserName="adm-helpdesk-t2")
| eval severity="CRITICAL"
| eval alert_title="🚨 CONFIRMED COMPROMISE: Honeytoken Successful Logon"
| eval LogonTypeDesc=case(
    LogonType=2, "Interactive (Console)",
    LogonType=3, "Network (SMB/RDP)",
    LogonType=4, "Batch",
    LogonType=5, "Service",
    LogonType=7, "Unlock",
    LogonType=8, "NetworkCleartext",
    LogonType=9, "NewCredentials (RunAs)",
    LogonType=10, "RemoteInteractive (RDP)",
    LogonType=11, "CachedInteractive",
    true(), "Unknown")
| table _time, TargetUserName, LogonType, LogonTypeDesc, IpAddress, WorkstationName, ProcessName, Computer
| sendalert pagerduty priority="critical"
```

---

### Rule 4: DCSync Detection (Event 4662)

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4662
ObjectType="domain"
(Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
(SubjectUserName="svc-sql-backup" OR SubjectUserName="svc-vmware-mgmt" OR SubjectUserName="adm-helpdesk-t2")
| eval severity="CRITICAL"
| eval attack_type="DCSync via Honeytoken"
| eval alert_title="🚨 DCSync Attack Detected - AD Replication Requested by Honeytoken"
| table _time, SubjectUserName, ObjectName, Properties, AccessMask, Computer
| sendalert pagerduty priority="critical"
```

---

## Microsoft Sentinel (Azure Sentinel)

### Rule 1: Kerberoasting Detection

**KQL Query**:
```kql
let HoneytokenSPNs = dynamic(["MSSQLSvc/sql-backup.corp.local:1433", "HTTP/vmware-mgmt.corp.local", "MSSQLSvc/sqlserver-ro.corp.local:1433"]);
SecurityEvent
| where EventID == 4769
| where ServiceName in (HoneytokenSPNs)
| extend IsRC4 = iff(TicketEncryptionType == "0x17", true, false)
| where IsRC4 == true
| extend AlertSeverity = "High"
| extend AttackType = "Kerberoasting"
| extend AlertTitle = strcat("🚨 Kerberoasting: ", ServiceName, " from ", IpAddress)
| project TimeGenerated, ServiceName, IpAddress, WorkstationName, TicketEncryptionType, Computer
```

**Analytics Rule Configuration**:
- Rule Name: `Honeytoken - Kerberoasting Detection`
- Severity: High
- Tactics: Credential Access (T1558.003)
- Frequency: 5 minutes
- Lookup Data: Last 5 minutes
- Alert Threshold: 1
- Action: Create incident, send email to SOC

---

### Rule 2: Honeytoken Authentication (All Events)

```kql
let HoneytokenAccounts = dynamic(["svc-sql-backup", "svc-vmware-mgmt", "adm-helpdesk-t2", "sqlserver-readonly", "svc-backup-exec"]);
SecurityEvent
| where EventID in (4768, 4769, 4776, 4624, 4625)
| where TargetUserName in (HoneytokenAccounts)
| extend AlertType = case(
    EventID == 4769, "Kerberoasting (TGS Request)",
    EventID == 4768, "TGT Request",
    EventID == 4776, "NTLM Authentication",
    EventID == 4624, "🔴 Successful Logon (CRITICAL)",
    EventID == 4625, "Failed Logon Attempt",
    "Unknown"
)
| extend Severity = iff(EventID == 4624, "Critical", "High")
| project TimeGenerated, EventID, AlertType, Severity, TargetUserName, IpAddress, WorkstationName, Computer
```

---

### Rule 3: DCSync Attack Detection

```kql
SecurityEvent
| where EventID == 4662
| where ObjectType == "domain"
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
| where SubjectUserName in ("svc-sql-backup", "svc-vmware-mgmt", "adm-helpdesk-t2", "sqlserver-readonly")
| extend AlertTitle = "🚨 DCSync Attack via Honeytoken"
| extend Severity = "High"
| extend AttackType = "DCSync (AD Replication)"
| project TimeGenerated, SubjectUserName, ObjectName, Properties, AccessMask, Computer
```

---

## Elasticsearch / ELK Stack

### Rule 1: Kerberoasting Detection

**Detection Rule (Kibana Alerts)**:
```json
{
  "name": "Honeytoken - Kerberoasting Detection",
  "tags": ["honeytoken", "kerberoasting", "credential-access"],
  "interval": "5m",
  "conditions": {
    "query": {
      "bool": {
        "must": [
          {
            "term": {
              "event.code": "4769"
            }
          },
          {
            "terms": {
              "winlog.event_data.ServiceName.keyword": [
                "MSSQLSvc/sql-backup.corp.local:1433",
                "HTTP/vmware-mgmt.corp.local",
                "MSSQLSvc/sqlserver-ro.corp.local:1433"
              ]
            }
          },
          {
            "term": {
              "winlog.event_data.TicketEncryptionType": "0x17"
            }
          }
        ]
      }
    }
  },
  "actions": {
    "email_alert": {
      "email": {
        "to": ["soc-team@corp.local"],
        "subject": "🚨 CRITICAL: Kerberoasting Attack on Honeytoken",
        "body": "Honeytoken SPN {{ctx.payload.hits.hits.0._source.winlog.event_data.ServiceName}} accessed from {{ctx.payload.hits.hits.0._source.source.ip}}. Immediate investigation required."
      }
    }
  }
}
```

---

### Rule 2: Honeytoken Authentication Events

**Elasticsearch Query DSL**:
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "terms": {
            "event.code": ["4768", "4769", "4776", "4624", "4625"]
          }
        },
        {
          "terms": {
            "winlog.event_data.TargetUserName.keyword": [
              "svc-sql-backup",
              "svc-vmware-mgmt",
              "adm-helpdesk-t2",
              "sqlserver-readonly",
              "svc-backup-exec"
            ]
          }
        }
      ]
    }
  },
  "aggs": {
    "by_event_type": {
      "terms": {
        "field": "event.code"
      }
    },
    "by_honeytoken": {
      "terms": {
        "field": "winlog.event_data.TargetUserName.keyword"
      }
    },
    "by_source_ip": {
      "terms": {
        "field": "source.ip"
      }
    }
  }
}
```

---

## Graylog

### Stream Rule: Honeytoken Access

**Stream Configuration**:
1. Create new stream: "Honeytoken Alerts"
2. Add matching rules:

**Rule 1**: Event ID matches
- Field: `EventID`
- Type: `match regular expression`
- Value: `^(4768|4769|4776|4624|4625|4662)$`

**Rule 2**: Honeytoken account
- Field: `TargetUserName`
- Type: `match regular expression`
- Value: `^(svc-sql-backup|svc-vmware-mgmt|adm-helpdesk-t2|sqlserver-readonly|svc-backup-exec)$`

**Alert Condition**:
```
Message count condition:
  Threshold type: MORE THAN
  Threshold: 0
  Time range: 5 minutes
  Grace period: 0 minutes
```

**Notification**:
```
Email Notification:
  Subject: 🚨 Honeytoken Access Alert
  Body: 
    Honeytoken account ${message.TargetUserName} accessed
    Event ID: ${message.EventID}
    Source: ${message.IpAddress}
    Workstation: ${message.WorkstationName}
    Time: ${message.timestamp}
```

---

## QRadar

### Custom Rule: Honeytoken Kerberoasting

**AQL Query**:
```sql
SELECT
  LOGSOURCENAME(logsourceid) AS 'Log Source',
  QIDNAME(qid) AS 'Event Name',
  username AS 'Honeytoken Account',
  sourceip AS 'Source IP',
  destinationip AS 'Domain Controller',
  DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS 'Time'
FROM events
WHERE
  (qid IN (SELECT qid FROM qidmap WHERE name LIKE '%4769%'))
  AND (
    username ILIKE 'svc-sql-backup' OR
    username ILIKE 'svc-vmware-mgmt' OR
    username ILIKE 'adm-helpdesk-t2'
  )
  AND (
    payload ILIKE '%0x17%'
  )
LAST 5 MINUTES
```

**Rule Configuration**:
- Rule Name: `Honeytoken - Kerberoasting Detection`
- Test Condition: `when the event(s) are detected by the Custom Rule Engine`
- Enable Rule Response: Yes
- Notification: `Email SOC Team`
- Severity: 9 (Critical)

---

## LogRhythm

### AIE Rule: Honeytoken Access

**Rule Definition**:
```xml
<Rule>
  <Name>Honeytoken - Authentication Attempt</Name>
  <CommonEvent>Security - Authentication Successful</CommonEvent>
  <CommonEvent>Security - Kerberos Ticket Requested</CommonEvent>
  <Filter>
    <OriginZone>Internal</OriginZone>
    <User Operator="Contains">svc-sql-backup</User>
    <User Operator="Contains">svc-vmware-mgmt</User>
    <User Operator="Contains">adm-helpdesk-t2</User>
  </Filter>
  <RiskRating>95</RiskRating>
  <Alarm>
    <AlarmRule>Honeytoken Access</AlarmRule>
    <AlarmStatus>New</AlarmStatus>
    <Priority>Critical</Priority>
    <Notification>Email SOC</Notification>
  </Alarm>
</Rule>
```

---

## AlienVault OSSIM / USM

### Correlation Directive

**Directive File** (`/etc/ossim/server/directives/honeytoken.xml`):
```xml
<directives>
  <directive id="900001" name="Honeytoken - Kerberos Activity" priority="5">
    <rule type="detector" name="Windows: Kerberos TGS Request" from="1" to="2" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="4769" reliability="10" occurrence="1">
      <rules>
        <rule type="detector" name="Honeytoken Account" from="1" to="2" port_from="ANY" port_to="ANY" plugin_id="1001" plugin_sid="4769" reliability="10" occurrence="1" userdata1="svc-sql-backup|svc-vmware-mgmt|adm-helpdesk-t2"/>
      </rules>
    </rule>
  </directive>
</directives>
```

---

## Testing Detection Rules

### Test Script (PowerShell)
```powershell
# test_honeytoken_detection.ps1
# Simulates honeytoken access to validate SIEM alerting

Write-Host "Testing Honeytoken Detection..." -ForegroundColor Cyan

# Test 1: Kerberoasting simulation (requires Rubeus)
if (Test-Path ".\Rubeus.exe") {
    Write-Host "`n[Test 1] Simulating Kerberoasting attack..."
    .\Rubeus.exe kerberoast /user:svc-sql-backup /nowrap
    Write-Host "Expected: Event 4769 alert within 60 seconds" -ForegroundColor Yellow
} else {
    Write-Warning "Rubeus.exe not found, skipping Kerberoasting test"
}

# Test 2: Authentication attempt
Write-Host "`n[Test 2] Simulating authentication attempt..."
$SecurePassword = Read-Host "Enter honeytoken password" -AsSecureString
$Credential = New-Object System.Management.Automation.PSCredential("corp\svc-sql-backup", $SecurePassword)

try {
    Test-Connection -ComputerName dc01.corp.local -Credential $Credential -ErrorAction Stop
} catch {
    Write-Host "Authentication failed (expected)" -ForegroundColor Green
}

Write-Host "Expected: Event 4776 or 4768 alert within 60 seconds" -ForegroundColor Yellow

Write-Host "`n[Test 3] Checking SIEM alert status..."
Write-Host "Check your SIEM dashboard for alerts matching 'Honeytoken'" -ForegroundColor Yellow
Write-Host "Expected alerts: 2 (Kerberoasting + Authentication)" -ForegroundColor Yellow
```

---

## Maintenance Schedule

### Daily
- [ ] Review honeytoken alert queue (should be zero if no compromise)
- [ ] Verify SIEM rule execution (check scheduled search logs)

### Weekly
- [ ] Audit honeytoken account status (ensure enabled, not locked out)
- [ ] Review false positive rate (should be 0% for honeytokens)

### Monthly
- [ ] Test detection rules with simulated attacks
- [ ] Verify honeytoken passwords not expired
- [ ] Update SIEM rules if new honeytokens deployed
- [ ] Audit SOC response time for honeytoken alerts

### Quarterly
- [ ] Review and update honeytoken naming strategy
- [ ] Audit all honeytoken configurations (SPNs, group memberships)
- [ ] Conduct tabletop exercise with SOC (honeytoken alert response)

---

## Troubleshooting

### No Alerts Firing

**Check 1**: Verify Event Forwarding
```powershell
# On Domain Controller
Get-WinEvent -LogName Security -MaxEvents 10 | Where-Object {$_.Id -eq 4769}
```

**Check 2**: Verify SIEM Ingestion
```spl
# Splunk
index=wineventlog EventCode=4769 | head 10

# Sentinel
SecurityEvent | where EventID == 4769 | take 10
```

**Check 3**: Verify Honeytoken Exists
```powershell
Get-ADUser -Identity "svc-sql-backup" -Properties ServicePrincipalNames
```

### Too Many False Positives

- Honeytokens should generate ZERO false positives
- If alerts firing, investigate all events (not false positives)
- Verify honeytoken accounts not being used by legitimate services

---

**Last Updated**: 2026-07-15  
**Version**: 1.0  
**Maintained by**: SOC Team
