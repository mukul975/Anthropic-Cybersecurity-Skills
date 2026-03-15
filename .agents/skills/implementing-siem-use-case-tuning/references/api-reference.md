# SIEM Use Case Tuning API Reference

## Splunk Notable Event Export

### Export Notables via SPL
```spl
| inputlookup notable_events
| search status_label IN ("New", "In Progress", "Resolved")
| table rule_name, _time, status_label, src, dest, user, urgency
| rename status_label as disposition, _time as timestamp
| outputlookup alert_export.csv
```

### Splunk ES Correlation Search Tuning
```spl
# Measure FP rate per correlation search over 30 days
| inputlookup notable_events where earliest=-30d
| eval is_fp=if(status_label="Resolved" AND disposition="False Positive", 1, 0)
| stats count as total, sum(is_fp) as fp_count by rule_name
| eval fp_rate=round(fp_count/total, 4)
| sort -fp_rate
```

### Update Correlation Search Threshold
```
POST /servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{search_name}
Content-Type: application/x-www-form-urlencoded

search=<updated_spl_with_new_threshold>
```

## Elastic Detection Rule Tuning

### List Detection Rules
```
GET /_security/detection_engine/rules/_find?per_page=100
Authorization: ApiKey <base64_api_key>
```

### Add Exception to Rule
```json
POST /_security/detection_engine/rules/exceptions
{
  "rule_id": "rule-uuid",
  "name": "Whitelist scanner IPs",
  "entries": [
    {
      "field": "source.ip",
      "operator": "is_one_of",
      "value": ["10.0.1.50", "10.0.1.51"],
      "type": "match_any"
    }
  ]
}
```

### Query Rule Execution Stats (Kibana)
```kql
event.kind: "signal" AND kibana.alert.rule.name: "Brute Force Detection"
| stats count by kibana.alert.workflow_status
```

## Alert Tuning Metrics

| Metric | Formula | Target |
|---|---|---|
| False Positive Rate | FP / (FP + TP) | < 30% |
| Precision | TP / (TP + FP) | > 70% |
| Alert-to-Incident Ratio | Incidents / Total Alerts | > 20% |
| Mean Time to Triage | avg(triage_end - alert_time) | < 15 min |

## CLI Usage

```bash
# Analyze alert CSV export
python agent.py --alert-csv notable_export.csv --output tuning.json

# Adjust FP threshold for whitelist candidates
python agent.py --alert-csv alerts.csv --fp-threshold 0.9 --top-rules 10

# CSV format: rule_name,timestamp,disposition,source,user,severity
```
