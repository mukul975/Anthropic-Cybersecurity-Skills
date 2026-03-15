# API Reference: Log Analysis for Forensic Investigation

## python-evtx Library

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        print(record.xml())
```

## Key Windows Security Event IDs

| Event ID | Description | Forensic Value |
|----------|-------------|----------------|
| 4624 | Successful logon | Track authentication patterns |
| 4625 | Failed logon | Brute force detection |
| 4648 | Explicit credentials | Lateral movement indicator |
| 4688 | Process creation | Command execution timeline |
| 4697 | Service installed | Persistence mechanism |
| 4698 | Scheduled task created | Persistence mechanism |
| 1102 | Audit log cleared | Anti-forensics detection |

## Syslog Parsing

| Log File | Content | Key Events |
|----------|---------|------------|
| `/var/log/auth.log` | SSH, sudo, su | Failed/successful SSH, privilege escalation |
| `/var/log/syslog` | General system | Service events, kernel messages |
| `/var/log/audit/audit.log` | auditd | File access, command execution |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `python-evtx` | >=0.7 | Windows EVTX event log parsing |
| `csv` | stdlib | Log data export and normalization |
| `re` | stdlib | Syslog and access log parsing |

## CLI Tools

| Tool | Command | Description |
|------|---------|-------------|
| evtxexport | `evtxexport Security.evtx` | Export EVTX to text |
| Chainsaw | `chainsaw hunt <evtx_dir> -s sigma/` | Sigma-based EVTX analysis |
| Hayabusa | `hayabusa csv-timeline -d <evtx_dir>` | Fast EVTX timeline generator |

## References

- python-evtx: https://github.com/williballenthin/python-evtx
- Chainsaw: https://github.com/WithSecureLabs/chainsaw
- Hayabusa: https://github.com/Yamato-Security/hayabusa
- Sigma rules: https://github.com/SigmaHQ/sigma
