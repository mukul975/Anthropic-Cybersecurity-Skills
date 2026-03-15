# Standards and References - Data Exfiltration Hunting

## MITRE ATT&CK Exfiltration (TA0010)

| Technique | Name | Channel |
|-----------|------|---------|
| T1041 | Exfiltration Over C2 Channel | Uses existing C2 connection |
| T1048.001 | Symmetric Encrypted Non-C2 | Custom encrypted protocol |
| T1048.002 | Asymmetric Encrypted Non-C2 | TLS to non-C2 server |
| T1048.003 | Unencrypted/Obfuscated Non-C2 | FTP, HTTP, raw TCP |
| T1567.001 | Exfiltration to Code Repository | GitHub, GitLab |
| T1567.002 | Exfiltration to Cloud Storage | S3, GDrive, Dropbox, OneDrive |
| T1567.003 | Exfiltration to Text Storage | Pastebin, paste.ee |
| T1567.004 | Exfiltration Over Webhook | Slack, Discord, Teams webhooks |
| T1052.001 | Exfiltration Over USB | Removable media |
| T1537 | Transfer Data to Cloud Account | Cloud-to-cloud exfiltration |
| T1020 | Automated Exfiltration | Script-based bulk transfer |
| T1029 | Scheduled Transfer | Periodic small transfers |
| T1030 | Data Transfer Size Limits | Size-limited staged transfer |

## Detection Thresholds

| Metric | Alert Threshold | Notes |
|--------|----------------|-------|
| Outbound data per host/day | > 2x 30-day average | Volume anomaly |
| DNS query length | > 50 characters | DNS tunneling indicator |
| DNS TXT record queries | > 100/hour per domain | DNS exfiltration |
| Cloud upload volume | > 500MB/day per user | Cloud exfiltration |
| Email attachment size | > 25MB per email | Email exfiltration |
| Off-hours data transfer | Any > 100MB | Unusual timing |
| Transfer to new destination | > 50MB first time | New destination risk |

## Data Sources

| Source | Event Type | Exfiltration Indicator |
|--------|-----------|----------------------|
| Proxy logs | HTTP POST/PUT | Large upload bytes |
| Firewall | Connection data | Bytes-out anomalies |
| DNS server | Query logs | Long subdomain names, TXT queries |
| Email gateway | Message logs | Attachment sizes, external recipients |
| CASB | Cloud activity | Uploads to personal cloud |
| Sysmon Event 3 | Network connections | Process-level data transfer |
| DLP | Content inspection | Sensitive data classification |
| USB audit | Removable media | Device insertion + file copy |
