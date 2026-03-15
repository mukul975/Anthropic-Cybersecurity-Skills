# Threat Intelligence Enrichment Template

## Feed Configuration

| Field | Value |
|---|---|
| Feed Name | |
| Source | |
| Feed Type | STIX/TAXII / CSV / API / Manual |
| Polling Interval | |
| IOC Types | IP / Domain / Hash / URL / Email |
| Confidence Threshold | |

## KV Store Collection

| Field | Type | Description |
|---|---|---|
| _key | string | Unique indicator hash |
| indicator_value | string | IOC value |
| threat_type | string | C2/Phishing/Malware/Scanner |
| confidence | number | 0-100 |
| source | string | Feed name |
| severity | string | critical/high/medium/low |
| first_seen | time | First observation |
| last_seen | time | Last observation |

## Correlation Search Template

```spl
| tstats summariesonly=true count
    from datamodel=<DataModel>
    by <fields>, _time span=5m
| rename "<DataModel>.*" as *
| lookup <lookup_name> <match_field> as <event_field>
    OUTPUT threat_type, confidence, source as ti_source
| where isnotnull(threat_type) AND confidence > <threshold>
| eval description="TI match: ".<matched_field>." (".<threat_type>.")"
```

## Feed Health Dashboard

| Metric | Current | Target |
|---|---|---|
| Total active indicators | | |
| Feed freshness (avg age) | | < 7 days |
| Hit rate (last 30 days) | | > 0.5% |
| False positive rate | | < 5% |
| Feed overlap rate | | < 30% |
