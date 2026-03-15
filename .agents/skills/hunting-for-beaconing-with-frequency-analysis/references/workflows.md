# Detailed Hunting Workflow - Beaconing Frequency Analysis

## Phase 1: Data Collection and Preparation

### Step 1.1 - Gather Network Connection Logs
Collect at minimum 24 hours (ideally 7 days) of:
- Proxy/firewall logs with timestamps, source/destination, bytes
- Zeek conn.log for connection metadata
- Zeek dns.log for DNS query analysis
- Zeek ssl.log for TLS certificate and JA3 fingerprinting
- NetFlow/IPFIX for high-level flow data

### Step 1.2 - Normalize Timestamps
Ensure all timestamps are in a consistent format (epoch or ISO 8601) and timezone (UTC). Misaligned timestamps will corrupt interval calculations.

## Phase 2: Statistical Frequency Analysis

### Step 2.1 - Splunk Interval Calculation
```spl
index=proxy OR index=firewall
| where NOT match(dest, "(?i)(microsoft|google|amazonaws|cloudflare|akamai|apple|adobe)")
| bin _time span=1s
| stats count by src_ip dest _time
| streamstats current=f last(_time) as prev_time by src_ip dest
| eval interval=_time-prev_time
| stats count avg(interval) as avg_interval stdev(interval) as stdev_interval
  min(interval) as min_interval max(interval) as max_interval
  dc(interval) as unique_intervals by src_ip dest
| where count > 50
| eval cv=stdev_interval/avg_interval
| eval jitter_pct=round((stdev_interval/avg_interval)*100, 1)
| where cv < 0.25 AND avg_interval > 30 AND avg_interval < 86400
| sort cv
| table src_ip dest count avg_interval stdev_interval cv jitter_pct
```

### Step 2.2 - Elastic Query for Beacon Detection
```json
{
  "aggs": {
    "by_pair": {
      "composite": {
        "sources": [
          {"src": {"terms": {"field": "source.ip"}}},
          {"dst": {"terms": {"field": "destination.domain"}}}
        ]
      },
      "aggs": {
        "timestamps": {
          "date_histogram": {"field": "@timestamp", "fixed_interval": "1s"}
        },
        "stats": {
          "extended_stats": {"field": "event.duration"}
        }
      }
    }
  }
}
```

### Step 2.3 - RITA Automated Analysis
```bash
# Import Zeek logs into RITA
rita import /path/to/zeek/logs mydataset

# Analyze beacons
rita show-beacons mydataset

# Export results as CSV
rita show-beacons mydataset --csv > beacon_results.csv

# Show long connections
rita show-long-connections mydataset
```

## Phase 3: Jitter-Aware Detection

### Step 3.1 - Detect Beacons with Jitter
Cobalt Strike adds configurable jitter (0-50%) to its sleep timer. A 60-second beacon with 30% jitter produces intervals between 42-78 seconds.

```spl
index=proxy
| stats count by src_ip dest _time
| streamstats current=f last(_time) as prev_time by src_ip dest
| eval interval=_time-prev_time
| stats count avg(interval) as avg stdev(interval) as sd
  percentile25(interval) as p25 percentile75(interval) as p75 by src_ip dest
| where count > 50
| eval iqr=p75-p25
| eval jitter_ratio=iqr/avg
| where jitter_ratio < 0.50 AND avg > 30
| sort jitter_ratio
```

## Phase 4: Data Size Consistency Analysis

### Step 4.1 - Payload Size Regularity
```spl
index=proxy
| stats count avg(bytes_out) as avg_bytes stdev(bytes_out) as sd_bytes
  by src_ip dest
| where count > 50
| eval data_cv=sd_bytes/avg_bytes
| where data_cv < 0.30
| sort data_cv
```

## Phase 5: Domain Intelligence Enrichment

### Step 5.1 - Check Domain Age via WHOIS
Flag any beaconing destination with domain registration under 30 days. Newly registered domains correlate strongly with C2 infrastructure.

### Step 5.2 - JA3/JA4 TLS Fingerprinting
```spl
index=zeek sourcetype=bro_ssl
| stats count dc(id.resp_h) as unique_dests values(server_name) as domains by ja3
| lookup ja3_known_c2 ja3 OUTPUT framework
| where isnotnull(framework)
| table ja3 framework count unique_dests domains
```

## Phase 6: Endpoint Correlation

### Step 6.1 - Map Network to Process
```spl
index=sysmon EventCode=3
| where NOT cidrmatch("10.0.0.0/8", DestinationIp)
  AND NOT cidrmatch("172.16.0.0/12", DestinationIp)
  AND NOT cidrmatch("192.168.0.0/16", DestinationIp)
| stats count values(DestinationPort) as ports dc(DestinationIp) as unique_ips
  by Image Computer DestinationIp
| where count > 50 AND unique_ips < 3
| sort -count
```

## Phase 7: Verification and Response

### Step 7.1 - Confirm C2 Activity
1. Capture packet sample of suspected C2 traffic
2. Analyze TLS certificate (self-signed, unusual issuer, short validity)
3. Cross-reference domain/IP against multiple TI sources
4. Review process tree on source endpoint
5. Check for associated lateral movement or tool transfers

### Step 7.2 - Containment Actions
1. Block C2 domain/IP at firewall, proxy, and DNS sinkhole
2. Isolate compromised endpoint via EDR network containment
3. Preserve memory dump and disk image for forensics
4. Reset credentials used on affected systems
5. Sweep environment for additional infections using discovered IOCs
