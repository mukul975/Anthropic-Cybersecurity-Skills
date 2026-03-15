# API Reference: Detecting Golden Ticket Attacks in Kerberos Logs

## Key Windows Event IDs

| Event ID | Description | Golden Ticket Signal |
|----------|-------------|---------------------|
| 4768 | TGT Requested (AS-REQ) | RC4 encryption, anomalous domain |
| 4769 | TGS Requested (TGS-REQ) | No prior 4768, forged TGT |
| 4771 | Kerberos Pre-Auth Failed | Non-existent account (0x6) |

## Kerberos Encryption Types

| Code | Algorithm | Suspicion |
|------|-----------|-----------|
| 0x11 | AES128-CTS | Normal (modern) |
| 0x12 | AES256-CTS | Normal (preferred) |
| 0x17 | RC4-HMAC | Suspicious (Mimikatz default) |
| 0x18 | RC4-HMAC-EXP | Suspicious |

## python-evtx Usage

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        # Parse Events 4768, 4769, 4771
        # Check TicketEncryptionType, TargetUserName
```

## Splunk SPL Detection

```spl
index=wineventlog EventCode=4769
| join type=left TargetUserName [
    search index=wineventlog EventCode=4768
    | rename TargetUserName as tgt_user
]
| where isnull(tgt_user)
| table _time TargetUserName ServiceName IpAddress Computer
```

## KQL (Microsoft Sentinel)

```kql
SecurityEvent
| where EventID == 4768
| where TicketEncryptionType in ("0x17", "0x18")
| where TargetUserName !endswith "$"
| project TimeGenerated, TargetUserName, IpAddress, TicketEncryptionType
```

## Mimikatz Golden Ticket Command

```
kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-... /krbtgt:hash /ptt
```

## CLI Usage

```bash
python agent.py --security-log Security.evtx --domain corp.local
python agent.py --generate-sigma
```
