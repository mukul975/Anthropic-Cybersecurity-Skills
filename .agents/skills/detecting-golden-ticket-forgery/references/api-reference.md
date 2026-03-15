# Golden Ticket Forgery Detection API Reference

## Windows Security Event IDs

### Event ID 4768 - TGT Requested (AS-REQ)
```
Key Fields:
  TargetUserName        - Account requesting TGT
  TargetDomainName      - Domain of requesting account
  IpAddress             - Source IP
  TicketEncryptionType  - 0x12 (AES256), 0x11 (AES128), 0x17 (RC4)
  PreAuthType           - 15 = PA-ENC-TIMESTAMP (normal)
```

### Event ID 4769 - TGS Requested (TGS-REQ)
```
Key Fields:
  TargetUserName        - Account using the ticket
  ServiceName           - SPN of target service
  IpAddress             - Source IP of requestor
  TicketEncryptionType  - 0x17 = RC4 (Golden Ticket indicator)
  TicketOptions         - Kerberos ticket flags
  LogonGuid             - Correlate with Event 4624
```

## Detection Indicators

| Indicator | Normal | Golden Ticket |
|---|---|---|
| TicketEncryptionType | 0x12 (AES256) | 0x17 (RC4-HMAC) |
| TGT Lifetime | <= 10 hours | Often 10+ years |
| TGS without TGT | Always preceded by 4768 | 4769 without 4768 |
| Domain field | Matches domain | May be blank or incorrect |

## Splunk SPL Queries

### RC4 TGS Detection (Golden Ticket)
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769
  TicketEncryptionType=0x17
  ServiceName!="krbtgt"
| stats count by TargetUserName, IpAddress, ServiceName
| where count > 3
| sort -count
```

### Orphaned TGS (No Prior TGT)
```spl
index=wineventlog EventCode=4769
| join type=left TargetUserName
  [search index=wineventlog EventCode=4768
   | dedup TargetUserName | fields TargetUserName]
| where isnull(TargetUserName)
| stats count by TargetUserName, IpAddress
```

### krbtgt Service Anomaly
```spl
index=wineventlog EventCode=4769 ServiceName="krbtgt*"
| table _time, TargetUserName, IpAddress, TicketEncryptionType
```

## Elastic KQL

### RC4 Downgrade in Elastic
```kql
event.code: "4769" AND winlog.event_data.TicketEncryptionType: "0x17"
  AND NOT winlog.event_data.ServiceName: "krbtgt"
```

## MITRE ATT&CK

| Technique | ID | Description |
|---|---|---|
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Forge TGT using krbtgt hash |

## CLI Usage
```bash
python agent.py --evtx-xml security_events.xml --output golden_ticket_report.json
python agent.py --show-splunk
python agent.py --evtx-xml events.xml --max-ticket-hours 8
```
