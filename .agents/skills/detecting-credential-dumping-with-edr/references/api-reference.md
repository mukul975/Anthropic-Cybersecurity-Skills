# API Reference: Detecting Credential Dumping with EDR

## T1003 Sub-Techniques

| Sub-technique | Method | Key Evidence |
|---------------|--------|--------------|
| T1003.001 | LSASS Memory | Sysmon Event ID 10, GrantedAccess mask |
| T1003.002 | SAM Registry | reg.exe save HKLM\SAM, Event ID 4656 |
| T1003.003 | NTDS.dit | vssadmin shadow copy, ntdsutil ifm |
| T1003.004 | LSA Secrets | Registry HKLM\SECURITY |
| T1003.005 | Cached Creds | DCC2 hashes in SECURITY hive |
| T1003.006 | DCSync | Event ID 4662, replication GUIDs |

## python-evtx Library

```python
import Evtx.Evtx as evtx

with evtx.Evtx("Sysmon.evtx") as log:
    for record in log.records():
        xml = record.xml()
        # Parse EventID, SourceImage, TargetImage, GrantedAccess
```

## LSASS Suspicious Access Masks

| GrantedAccess | Meaning |
|---------------|---------|
| 0x1010 | PROCESS_VM_READ + QUERY_INFO (Mimikatz) |
| 0x1038 | VM_READ + QUERY_INFO + VM_WRITE |
| 0x1FFFFF | PROCESS_ALL_ACCESS |

## DCSync Replication GUIDs

```
DS-Replication-Get-Changes:             1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
DS-Replication-Get-Changes-All:         1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
DS-Replication-Get-Changes-In-Filtered: 89e95b76-444d-4c62-991a-0facbeda640c
```

## Splunk SPL - LSASS Access Detection

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage, "(csrss|services|svchost|lsm|MsMpEng)\\.exe$")
| where GrantedAccess IN ("0x1010", "0x1038", "0x1FFFFF")
| table _time SourceImage GrantedAccess Computer SourceUser
```

## KQL - Microsoft Defender for Endpoint

```kql
DeviceProcessEvents
| where FileName in ("mimikatz.exe", "procdump.exe", "nanodump.exe")
   or ProcessCommandLine has_any ("sekurlsa", "lsadump", "MiniDump")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
```

## CLI Usage

```bash
python agent.py --sysmon-log Sysmon.evtx
python agent.py --security-log Security.evtx
python agent.py --command-log process_audit.log
```
