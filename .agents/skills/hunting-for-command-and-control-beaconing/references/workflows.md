# Detailed Hunting Workflow - C2 Beaconing Detection

## Phase 1: HTTP/HTTPS Beacon Detection

### Step 1.1 - Splunk Frequency Analysis
```spl
index=proxy OR index=firewall
| where NOT match(dest, "(?i)(microsoft|google|amazonaws|cloudflare|akamai)")
| bin _time span=1s
| stats count by src_ip dest _time
| streamstats current=f last(_time) as prev_time by src_ip dest
| eval interval=_time-prev_time
| stats count avg(interval) as avg_interval stdev(interval) as stdev_interval min(interval) as min_interval max(interval) as max_interval by src_ip dest
| where count > 50
| eval cv=stdev_interval/avg_interval
| where cv < 0.20 AND avg_interval > 30 AND avg_interval < 86400
| sort cv
| table src_ip dest count avg_interval stdev_interval cv
```

### Step 1.2 - KQL Beacon Detection
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| summarize ConnectionTimes=make_list(Timestamp), Count=count() by DeviceName, RemoteIP, RemoteUrl
| where Count > 50
| extend Intervals = array_sort_asc(ConnectionTimes)
| mv-apply Intervals on (
    extend NextTime = next(Intervals)
    | where isnotempty(NextTime)
    | extend IntervalSec = datetime_diff('second', NextTime, Intervals)
    | summarize AvgInterval=avg(IntervalSec), StdDev=stdev(IntervalSec)
)
| extend CV = StdDev / AvgInterval
| where CV < 0.2 and AvgInterval > 30
```

## Phase 2: DNS Beaconing and Tunneling

### Step 2.1 - DNS Query Frequency Analysis
```spl
index=dns
| rex field=query "(?<subdomain>[^.]+)\.(?<domain>[^.]+\.[^.]+)$"
| stats count dc(subdomain) as unique_subdomains avg(len(query)) as avg_query_len by src_ip domain
| where count > 100 AND (unique_subdomains > 50 OR avg_query_len > 40)
| sort -count
```

### Step 2.2 - DNS Entropy Analysis
```spl
index=dns query_type IN ("TXT", "NULL", "CNAME", "MX")
| rex field=query "^(?<subdomain>[^.]+)"
| eval entropy=0
| foreach * [eval entropy=entropy]
| where len(subdomain) > 20
| stats count by src_ip query domain
| where count > 20
```

### Step 2.3 - RITA-Style Beacon Analysis
RITA automatically analyzes Zeek logs for:
- Connection frequency with jitter tolerance
- DNS tunneling indicators
- Long connection durations
- Unusual user agents

## Phase 3: JA3/JA4 TLS Fingerprinting

### Step 3.1 - Unusual TLS Fingerprints
```spl
index=zeek sourcetype=bro_ssl
| stats count dc(id.resp_h) as unique_dests values(id.resp_h) as destinations by ja3 ja3s
| where count > 10
| lookup ja3_known_bad ja3
| where match="true"
| table ja3 ja3s count unique_dests destinations
```

### Step 3.2 - Self-Signed Certificate Detection
```spl
index=zeek sourcetype=bro_ssl
| where validation_status!="ok"
| stats count by id.orig_h id.resp_h server_name validation_status
| where count > 10
| sort -count
```

## Phase 4: Process-Level Correlation

### Step 4.1 - Map Processes to Network Connections
```spl
index=sysmon EventCode=3
| where NOT match(DestinationIp, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
| stats count values(DestinationPort) as ports dc(DestinationIp) as unique_ips by Image Computer
| where count > 50 AND unique_ips < 5
| sort -count
```

### Step 4.2 - Unusual Process Network Activity
```spl
index=sysmon EventCode=3
| where match(Image, "(?i)(notepad|calc|mspaint|write|wordpad)")
| stats count by Image DestinationIp DestinationPort Computer
```

## Phase 5: Domain Intelligence

### Step 5.1 - New/Young Domain Detection
Check domains seen in beaconing analysis:
- WHOIS creation date < 30 days
- Domain registered with privacy protection
- Hosting on bulletproof infrastructure
- No historical passive DNS data

### Step 5.2 - DGA Domain Detection
Indicators of algorithmically generated domains:
- High character entropy (> 3.5 bits per char)
- No dictionary words in domain
- Unusual TLD combinations
- Sequential registration patterns

## Phase 6: Verification and Response

### Step 6.1 - Confirm C2 Activity
1. Capture packet sample of suspected C2 traffic
2. Analyze TLS certificate details
3. Check domain/IP against multiple TI sources
4. Review endpoint process tree
5. Look for associated file drops or tool transfers

### Step 6.2 - Response Actions
1. Block C2 domain/IP at firewall and proxy
2. Isolate compromised endpoint(s)
3. Preserve forensic evidence
4. Reset credentials used on affected systems
5. Hunt for additional infected hosts using same IOCs
