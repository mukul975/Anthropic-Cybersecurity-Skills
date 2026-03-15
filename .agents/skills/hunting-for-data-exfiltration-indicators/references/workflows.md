# Detailed Hunting Workflow - Data Exfiltration

## Phase 1: Volume Anomaly Detection

### Step 1.1 - Outbound Data Volume per Host
```spl
index=proxy OR index=firewall
| where NOT match(dest, "(?i)(microsoft|windowsupdate|google|amazonaws)")
| stats sum(bytes_out) as total_bytes_out by src_ip
| eval MB_out=round(total_bytes_out/1048576, 2)
| sort -MB_out
| head 50
```

### Step 1.2 - Statistical Volume Anomaly
```spl
index=proxy earliest=-30d
| bin _time span=1d
| stats sum(bytes_out) as daily_bytes by src_ip _time
| eventstats avg(daily_bytes) as avg_daily stdev(daily_bytes) as sd_daily by src_ip
| where daily_bytes > (avg_daily + 3*sd_daily) AND daily_bytes > 104857600
| eval anomaly_factor=round(daily_bytes/avg_daily, 1)
| table _time src_ip daily_bytes avg_daily anomaly_factor
```

## Phase 2: Cloud Storage Exfiltration

### Step 2.1 - Cloud Upload Detection
```spl
index=proxy
| where match(dest, "(?i)(drive\.google|dropbox|box\.com|onedrive|mega\.nz|wetransfer|sendspace)")
| where method IN ("POST", "PUT")
| stats sum(bytes_out) as uploaded_bytes count by src_ip dest user
| eval MB_uploaded=round(uploaded_bytes/1048576, 2)
| where MB_uploaded > 50
| sort -MB_uploaded
```

## Phase 3: DNS Exfiltration

### Step 3.1 - DNS Tunneling Indicators
```spl
index=dns
| eval query_len=len(query)
| where query_len > 50
| rex field=query "^(?<subdomain>.+)\.(?<base_domain>[^.]+\.[^.]+)$"
| stats count avg(query_len) as avg_len dc(subdomain) as unique_subs by src_ip base_domain
| where count > 100 AND (avg_len > 40 OR unique_subs > 50)
| sort -count
```

## Phase 4: Email Exfiltration

### Step 4.1 - Large Email Attachments to External
```spl
index=email
| where match(recipient, "(?i)(gmail|yahoo|hotmail|protonmail|outlook)")
| where attachment_size > 10485760
| stats count sum(attachment_size) as total_size by sender recipient
| eval MB_sent=round(total_size/1048576, 2)
| sort -MB_sent
```

## Phase 5: File Access Correlation

### Step 5.1 - Sensitive File Access Before Exfiltration
Correlate file access events on sensitive shares with subsequent outbound data transfers:
```spl
index=wineventlog EventCode=5145
| where match(Share_Name, "(?i)(finance|hr|legal|confidential|restricted)")
| stats count values(Relative_Target_Name) as files by Account_Name Source_Address
| join Account_Name [
    search index=proxy method IN ("POST","PUT") earliest=-1h
    | stats sum(bytes_out) as upload_bytes by user
    | rename user as Account_Name
]
| where upload_bytes > 1048576
```
