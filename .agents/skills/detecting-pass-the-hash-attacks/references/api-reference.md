# API Reference: Detecting Pass-the-Hash Attacks

## Windows Event ID 4624 Fields

| Field | PtH Signal |
|-------|------------|
| LogonType | 3 (Network) |
| AuthenticationPackageName | NTLM (not Kerberos) |
| LogonProcessName | NtLmSsp |
| IpAddress | Source of authentication |
| TargetUserName | Account being used |

## python-evtx Usage

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        # Filter EventID 4624, LogonType=3, AuthPackage=NTLM
```

## PtH Detection Logic

```python
src_targets = defaultdict(set)
for event in ntlm_logons:
    src_targets[event["source_ip"]].add(event["computer"])
# Alert when single source authenticates to 3+ targets via NTLM
```

## Splunk SPL Detection

```spl
index=wineventlog EventCode=4624 Logon_Type=3
| where Authentication_Package="NTLM"
| stats dc(Computer) as targets by Source_Network_Address, Account_Name
| where targets >= 3
| sort -targets
```

## KQL (Microsoft Sentinel)

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| summarize TargetCount=dcount(Computer) by IpAddress, TargetUserName
| where TargetCount >= 3
```

## Mitigation

```powershell
# Restrict NTLM authentication
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictSendingNTLMTraffic" -Value 2
```

## CLI Usage

```bash
python agent.py --security-log Security.evtx
python agent.py --security-log Security.evtx --target-threshold 5
```
