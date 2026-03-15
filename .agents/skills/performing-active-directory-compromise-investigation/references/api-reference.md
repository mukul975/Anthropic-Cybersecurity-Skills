# Active Directory Compromise Investigation - API Reference

## Windows Security Event IDs

| Event ID | Description | Compromise Indicator |
|----------|-------------|---------------------|
| 4662 | Directory service object accessed | DCSync (replication GUIDs) |
| 4769 | Kerberos service ticket requested | Kerberoasting (RC4 encryption) |
| 4768 | Kerberos TGT requested | Golden Ticket (anomalous source) |
| 4672 | Special privileges assigned | Privileged logon tracking |
| 4624 | Successful logon | Lateral movement (Type 3) |
| 4648 | Explicit credential logon | Pass-the-hash, PsExec |
| 4720 | User account created | Persistence |
| 4728 | Member added to global group | Privilege escalation |
| 4732 | Member added to local group | Privilege escalation |

## DCSync Detection

### Replication GUIDs (Event 4662 ObjectType)

| GUID | Right |
|------|-------|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

When a non-DC account triggers 4662 with these GUIDs, it indicates DCSync attack (Mimikatz lsadump::dcsync).

## Kerberoasting Detection

Event 4769 with `TicketEncryptionType = 0x17` (RC4-HMAC) for service accounts. Normal behavior uses AES (0x11 or 0x12). RC4 requests by user accounts against service SPNs indicate offline cracking attempts.

## Golden Ticket Detection

Event 4768 TGT requests from IPs that are not domain controllers. Golden tickets forged offline will show TGT requests from workstations rather than DCs.

## Lateral Movement Detection

- **Type 3 logon** (Event 4624, LogonType=3): Network logon via SMB, WMI, PsExec
- **Event 4648**: Explicit credential use (runas, remote tools)
- Pattern: Multiple Type 3 logons from same source to different targets

## Event Log JSON Format

The agent accepts JSON-exported event logs:
```json
[
  {
    "EventID": 4769,
    "TimeCreated": "2024-01-15T10:30:00Z",
    "EventData": {
      "TargetUserName": "svc_sql",
      "ServiceName": "MSSQLSvc/db01:1433",
      "TicketEncryptionType": "0x17"
    }
  }
]
```

Export from PowerShell:
```powershell
Get-WinEvent -LogName Security | ConvertTo-Json -Depth 5 > events.json
```

## Output Schema

```json
{
  "report": "ad_compromise_investigation",
  "total_events_analyzed": 50000,
  "total_findings": 15,
  "severity_summary": {"critical": 3, "high": 7, "medium": 5},
  "findings": [{"type": "dcsync_detected", "severity": "critical"}]
}
```

## CLI Usage

```bash
python agent.py --log events.json --output report.json
```
