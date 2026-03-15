# API Reference: Beaconing Detection via Frequency Analysis

## Beaconing Characteristics

| Characteristic | Description |
|---------------|-------------|
| Regular intervals | Connections at fixed time periods |
| Low jitter | Small variance in intervals |
| Persistent | Continues over hours/days |
| Consistent size | Similar packet sizes |

## Jitter Calculation

### Standard Deviation of Intervals
```python
import math
intervals = [t[i+1] - t[i] for i in range(len(t)-1)]
mean = sum(intervals) / len(intervals)
variance = sum((x - mean)**2 for x in intervals) / len(intervals)
jitter = math.sqrt(variance)
jitter_percent = (jitter / mean) * 100
```

### Jitter Thresholds
| Jitter % | Confidence | Likely Cause |
|----------|------------|--------------|
| < 5% | HIGH | Automated C2 beacon |
| 5-15% | MEDIUM | Possible C2 with sleep jitter |
| 15-30% | LOW | May be legitimate polling |
| > 30% | NONE | Likely human/random |

## Zeek conn.log Format

### Fields
| Index | Name | Description |
|-------|------|-------------|
| 0 | ts | Unix timestamp |
| 2 | id.orig_h | Source IP |
| 3 | id.orig_p | Source port |
| 4 | id.resp_h | Destination IP |
| 5 | id.resp_p | Destination port |
| 6 | proto | Protocol |
| 9 | orig_bytes | Sent bytes |
| 10 | resp_bytes | Received bytes |

## RITA (Real Intelligence Threat Analytics)

### Analyze Zeek Logs
```bash
rita import /path/to/zeek/logs dataset_name
rita show-beacons dataset_name
```

### Output Columns
| Column | Description |
|--------|-------------|
| Score | Beacon probability (0-1) |
| Source | Source IP |
| Destination | Destination IP |
| Connections | Total connections |
| Avg Bytes | Average data transfer |

## Splunk SPL — Beacon Detection

```spl
index=network sourcetype=zeek:conn
| bin _time span=60s
| stats count by src_ip, dest_ip, dest_port, _time
| streamstats window=100 stdev(count) as jitter avg(count) as avg_count by src_ip, dest_ip
| where jitter/avg_count < 0.15
| stats count as beacon_count by src_ip, dest_ip, dest_port
| where beacon_count > 100
```

## Elastic SIEM — Beacon Detection

```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"exists": {"field": "destination.ip"}}
      ]
    }
  },
  "aggs": {
    "by_flow": {
      "composite": {
        "sources": [
          {"src": {"terms": {"field": "source.ip"}}},
          {"dst": {"terms": {"field": "destination.ip"}}}
        ]
      }
    }
  }
}
```

## Common C2 Beacon Intervals

| Framework | Default Interval |
|-----------|-----------------|
| Cobalt Strike | 60 seconds |
| Metasploit | 5 seconds |
| Empire | 5 seconds |
| Covenant | 10 seconds |
| Sliver | 60 seconds |
