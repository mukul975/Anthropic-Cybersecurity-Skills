# Pass-the-Ticket Detection API Reference

## Windows Security Event IDs

### Event ID 4768 - TGT Requested
```
Key Fields:
  TargetUserName      - Account requesting TGT
  TargetDomainName    - Domain of account
  IpAddress           - Source IP of request
  TicketEncryptionType - 0x12 (AES256), 0x17 (RC4-HMAC)
  PreAuthType         - 15 (PA-ENC-TIMESTAMP)
```

### Event ID 4769 - TGS Requested
```
Key Fields:
  TargetUserName      - Account using the ticket
  ServiceName         - SPN of requested service
  IpAddress           - Source IP
  TicketEncryptionType - 0x17 indicates RC4 downgrade
  TicketOptions       - Kerberos ticket flags
```

### Event ID 4771 - Kerberos Pre-Authentication Failed
```
Key Fields:
  TargetUserName      - Account that failed
  IpAddress           - Source of failure
  Status              - 0x18 (wrong password), 0x12 (expired)
```

## Splunk SPL Queries

### RC4 Encryption Downgrade Detection
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769
  TicketEncryptionType=0x17
| stats count by TargetUserName, IpAddress, ServiceName
| where count > 3
```

### Cross-Host Ticket Reuse
```spl
index=wineventlog EventCode=4769
| stats dc(IpAddress) as ip_count, values(IpAddress) as ips
  by TargetUserName
| where ip_count > 1
| sort -ip_count
```

### TGS Volume Anomaly
```spl
index=wineventlog EventCode=4769
| bin _time span=1h
| stats count by TargetUserName, _time
| eventstats avg(count) as avg_count, stdev(count) as sd by TargetUserName
| where count > avg_count + (3 * sd)
```

## Elastic / KQL Queries

### RC4 Downgrade in Elastic
```kql
event.code: "4769" AND winlog.event_data.TicketEncryptionType: "0x17"
```

### Cross-Host Reuse in Elastic
```json
POST security-*/_search
{
  "size": 0,
  "query": { "term": { "event.code": "4769" } },
  "aggs": {
    "by_user": {
      "terms": { "field": "winlog.event_data.TargetUserName" },
      "aggs": {
        "unique_ips": { "cardinality": { "field": "source.ip" } }
      }
    }
  }
}
```

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Use Alternate Authentication Material: Pass the Ticket | T1550.003 | RC4 downgrade, cross-host reuse |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | High TGS volume for SPNs |
| Brute Force: Password Spraying | T1110.003 | Pre-auth failure spikes |

## CLI Usage

```bash
# Parse exported event log XML and detect PtT indicators
python agent.py --evtx-xml security_events.xml --output report.json

# Show Splunk detection queries
python agent.py --show-splunk

# Custom thresholds
python agent.py --evtx-xml events.xml --tgs-threshold 30 --preauth-threshold 5
```
