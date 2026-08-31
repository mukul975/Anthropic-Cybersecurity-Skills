# NTLM Downgrade, Coercion, and Dashboard Queries

Companion depth for `SKILL.md` Steps 5, 7, and 8. NTLMv1 downgrade detection,
PetitPotam/DFSCoerce/PrinterBug coercion detection, and the combined correlation
dashboard.

## NTLM Downgrade Detection (Step 5)

NTLMv1 is weaker and easier to relay/crack than NTLMv2 and should not be in use.
NTLMv1 appearing after a period of only NTLMv2 suggests an active downgrade.

```spl
# Splunk: Detect NTLMv1 Authentication (Downgrade from NTLMv2)
# NTLMv1 is weaker and easier to relay/crack -- should not be in use

index=wineventlog EventCode=4624 LogonType=3
    LmPackageName="NTLM V1"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| stats count values(ComputerName) as targets
    values(IpAddress) as source_ips
    by TargetUserName LmPackageName
| table TargetUserName LmPackageName source_ips targets count
| sort -count
```

```spl
# Splunk: Detect NTLM Downgrade Attack Pattern
# NTLMv1 appearing after a period of only NTLMv2 suggests active downgrade

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
| bin _time span=1h
| stats count(eval(LmPackageName="NTLM V1")) as ntlmv1_count
    count(eval(LmPackageName="NTLM V2")) as ntlmv2_count
    by _time
| where ntlmv1_count > 0
| eval ntlmv1_ratio = round(ntlmv1_count / (ntlmv1_count + ntlmv2_count) * 100, 2)
| table _time ntlmv1_count ntlmv2_count ntlmv1_ratio
| sort -_time
```

```kql
-- Microsoft Sentinel KQL: NTLMv1 Downgrade Detection

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where LmPackageName == "NTLM V1"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| project TimeGenerated, Computer, TargetUserName, WorkstationName,
    IpAddress, LmPackageName, LogonProcessName
| sort by TimeGenerated desc
```

```powershell
# PowerShell: Detect NTLMv1 Authentication Events on Local System

$ntlmv1Events = Get-WinEvent -LogName Security -FilterXPath @"
*[System[(EventID=4624)]]
 and
*[EventData[Data[@Name='LmPackageName']='NTLM V1']]
"@ -MaxEvents 500 -ErrorAction SilentlyContinue

if ($ntlmv1Events.Count -gt 0) {
    Write-Host "[!] WARNING: $($ntlmv1Events.Count) NTLMv1 authentication events detected!" -ForegroundColor Red
    $ntlmv1Events | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        [PSCustomObject]@{
            Time         = $_.TimeCreated
            TargetUser   = ($eventData | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            Workstation  = ($eventData | Where-Object { $_.Name -eq "WorkstationName" }).'#text'
            SourceIP     = ($eventData | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            LmPackage    = ($eventData | Where-Object { $_.Name -eq "LmPackageName" }).'#text'
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "[+] No NTLMv1 authentication events found (Good)" -ForegroundColor Green
}

# Audit GPO settings for NTLM restriction
Write-Host "`n=== NTLM RESTRICTION POLICY ==="
$ntlmPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

$level = switch ($ntlmPolicy.LmCompatibilityLevel) {
    0 { "Send LM & NTLM responses (Most Vulnerable)" }
    1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
    2 { "Send NTLM response only" }
    3 { "Send NTLMv2 response only (Recommended minimum)" }
    4 { "Send NTLMv2 response only, refuse LM" }
    5 { "Send NTLMv2 response only, refuse LM & NTLM (Most Secure)" }
    default { "Not configured (defaults to 3 on modern Windows)" }
}
Write-Host "[*] LmCompatibilityLevel: $($ntlmPolicy.LmCompatibilityLevel) - $level"
```

## PetitPotam and Coercion Attack Detection (Step 7)

```spl
# Splunk: Detect PetitPotam / EFSCoerce Attack
# Monitor for machine account NTLM authentications relayed to other services

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
    TargetUserName="*$"
| where match(TargetUserName, "^[A-Z0-9\\-]+\\$$")
| eval is_dc = if(match(TargetUserName, "(DC|DCSERVER|DOMCTRL)"), "Yes", "No")
| where IpAddress != "127.0.0.1" AND IpAddress != "::1"
| stats count values(ComputerName) as target_hosts
    values(IpAddress) as source_ips by TargetUserName
| where count > 2 OR mvcount(source_ips) > 1
| table TargetUserName source_ips target_hosts count
| sort -count
```

```kql
-- Microsoft Sentinel KQL: PetitPotam / Coercion Attack Detection
-- Detects domain controller machine account authenticating from unexpected IPs

let dc_accounts = SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TargetUserName endswith "$"
| where Computer startswith "DC"
| distinct TargetUserName;

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName in (dc_accounts)
| where IpAddress != "127.0.0.1" and IpAddress != "::1"
| extend SourceHostExpected = iff(
    Computer == replace_string(TargetUserName, "$", ""), true, false)
| where SourceHostExpected == false
| project TimeGenerated, Computer, TargetUserName, IpAddress,
    WorkstationName, LogonProcessName, AuthenticationPackageName
| sort by TimeGenerated desc
```

```yaml
# Sigma Rule: NTLM Relay - Computer Account Authentication from Unexpected Source
title: Potential NTLM Relay of Computer Account Credentials
id: 5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: stable
description: >
  Detects a computer account (ending in $) authenticating via NTLM LogonType 3
  where the source IP does not match the computer's known IP, indicating possible
  NTLM relay of coerced machine authentication (PetitPotam, DFSCoerce, PrinterBug).
references:
    - https://www.crowdstrike.com/en-us/blog/how-to-detect-domain-controller-account-relay-attacks-with-crowdstrike-identity-protection/
    - https://www.fox-it.com/nl-en/research-blog/detecting-and-hunting-for-the-petitpotam-ntlm-relay-attack/
    - https://www.nccgroup.com/research-blog/detecting-and-hunting-for-the-petitpotam-ntlm-relay-attack/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: NTLM
        TargetUserName|endswith: '$'
    filter_localhost:
        IpAddress:
            - '127.0.0.1'
            - '::1'
            - '-'
    condition: selection and not filter_localhost
level: high
tags:
    - attack.credential_access
    - attack.t1557.001
    - attack.t1187
falsepositives:
    - Legitimate NTLM authentication from machine accounts during failover
    - Cluster service machine account authentication
```

## Comprehensive Correlation Dashboard (Step 8)

```spl
# Splunk: NTLM Relay Detection Dashboard -- Combined Correlation Query

# Panel 1: IP-Hostname Mismatches (Core Relay Indicator)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON" AND NOT match(TargetUserName, ".*\\$$")
| eval mismatch=if(lower(WorkstationName) != lower(mvindex(split(IpAddress, "."), 0)),
    "POSSIBLE_MISMATCH", "OK")
| where mismatch="POSSIBLE_MISMATCH"
| stats count by TargetUserName WorkstationName IpAddress ComputerName

# Panel 2: NTLMv1 Downgrade Events
index=wineventlog EventCode=4624 LmPackageName="NTLM V1"
| timechart span=1h count by ComputerName

# Panel 3: Machine Account Relay (PetitPotam Indicator)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
    TargetUserName="*$"
| stats count values(IpAddress) as relay_sources by TargetUserName ComputerName

# Panel 4: NTLM Authentication Volume Anomaly
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| timechart span=15m count
| streamstats window=20 avg(count) as avg_count stdev(count) as stdev_count
| eval upper_bound=avg_count + (3 * stdev_count)
| where count > upper_bound

# Panel 5: SMB Signing Status (from audit results)
| inputlookup smb_signing_audit.csv
| stats count by Status
| table Status count
```
