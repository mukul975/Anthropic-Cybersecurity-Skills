# API Reference: Detecting RDP Brute Force Attacks

## Windows Security Event IDs

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 4625 | Failed logon attempt | TargetUserName, IpAddress, SubStatus, LogonType |
| 4624 | Successful logon | TargetUserName, IpAddress, LogonType |
| 4776 | NTLM credential validation | TargetUserName, Workstation, Status |
| 4771 | Kerberos pre-auth failed | TargetUserName, IpAddress, Status |

## Logon Types for RDP

| Type | Name | Context |
|------|------|---------|
| 3 | Network | RDP with NLA enabled (pre-auth) |
| 10 | RemoteInteractive | RDP session after NLA |

## Failure Sub-Status Codes

| Sub-Status | Meaning |
|------------|---------|
| 0xC0000064 | User does not exist |
| 0xC000006A | Wrong password |
| 0xC0000234 | Account locked out |
| 0xC0000072 | Account disabled |
| 0xC0000193 | Account expired |
| 0xC0000071 | Password expired |

## python-evtx Library Usage

```python
import Evtx.Evtx as evtx

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml_str = record.xml()
```

Install: `pip install python-evtx lxml`

## wevtutil Export Commands

```bash
# Export Security log to EVTX
wevtutil epl Security C:\logs\security.evtx

# Query failed RDP logons
wevtutil qe Security /q:"*[System[(EventID=4625)] and EventData[Data[@Name='LogonType']='10']]" /f:text

# Count recent failed logons
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:100 /rd:true /f:text
```

## Detection Thresholds

| Pattern | Threshold | Indicator |
|---------|-----------|-----------|
| Brute force | >10 failures/IP in 15 min | Single-target credential guessing |
| Password spray | >5 unique users/IP | Multi-user single-password attack |
| Compromise | 4625 followed by 4624 from same IP | Successful brute force |

## References

- Microsoft Event 4625: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Event 4624: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- python-evtx: https://github.com/williballenthin/python-evtx
- LogonTracer: https://github.com/JPCERTCC/LogonTracer
