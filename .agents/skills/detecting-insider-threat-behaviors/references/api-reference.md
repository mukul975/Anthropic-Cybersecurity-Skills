# API Reference: Detecting Insider Threat Behaviors

## Risk Indicator Weights

| Indicator | Weight | Description |
|-----------|--------|-------------|
| resignation_correlated | 35 | Activity after resignation notice |
| privilege_escalation | 30 | Unauthorized privilege use |
| usb_mass_copy | 30 | Mass copy to removable media |
| mass_download | 25 | Bulk file download/copy (>50 files) |
| unusual_destination | 20 | Data sent to unusual destination |
| cloud_upload | 20 | Upload to personal cloud storage |
| off_hours_access | 15 | Activity outside 8am-6pm |
| email_to_personal | 15 | Forwarding to personal email |

## UEBA Data Sources

| Source | Indicators |
|--------|------------|
| DLP logs | File downloads, USB copies, email attachments |
| Proxy logs | Cloud storage uploads, personal email |
| VPN logs | Off-hours access, unusual locations |
| AD logs | Privilege changes, group modifications |
| Endpoint logs | Application usage, screen captures |

## Splunk SPL - Mass Download Detection

```spl
index=dlp action IN ("download", "copy", "export")
| bin _time span=1h
| stats count by user, _time
| where count > 50
| sort -count
```

## Microsoft Sentinel - Off-Hours Access

```kql
SigninLogs
| where TimeGenerated between (datetime(22:00)..datetime(06:00))
| where ResultType == 0
| summarize count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where count_ > 5
```

## Personal Cloud Domains

```python
CLOUD_STORAGE = {
    "dropbox.com", "drive.google.com",
    "onedrive.live.com", "box.com",
    "mega.nz", "wetransfer.com"
}
```

## Risk Score Calculation

```python
score = sum(RISK_INDICATORS[ind]["weight"] for ind in detected_indicators)
risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM"
```

## CLI Usage

```bash
python agent.py --activity-log user_activity.jsonl
python agent.py --activity-log events.csv --download-threshold 100
```
