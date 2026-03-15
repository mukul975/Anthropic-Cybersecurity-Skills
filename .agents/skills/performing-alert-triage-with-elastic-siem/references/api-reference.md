# Alert Triage with Elastic SIEM - API Reference

## elasticsearch-py Client

### Connection
```python
from elasticsearch import Elasticsearch
es = Elasticsearch(
    hosts=["https://elastic:9200"],
    api_key="base64-api-key",
    verify_certs=True
)
```

### SIEM Signals Index
Elastic Security stores alerts in `.siem-signals-<space>-*` indices.

## Querying Alerts

### Search Open Alerts
```python
es.search(
    index=".siem-signals-*",
    query={"bool": {"must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"term": {"signal.status": "open"}}
    ]}},
    sort=[{"@timestamp": {"order": "desc"}}],
    size=500
)
```

### Alert Fields

| Field | Path | Description |
|-------|------|-------------|
| Rule name | `signal.rule.name` | Detection rule that triggered |
| Rule ID | `signal.rule.id` | Unique rule identifier |
| Severity | `signal.rule.severity` | critical, high, medium, low |
| Risk score | `signal.rule.risk_score` | 0-100 numeric score |
| Status | `signal.status` | open, acknowledged, closed |
| Source IP | `source.ip` | Alert source address |
| Destination IP | `destination.ip` | Alert destination address |
| User | `user.name` | Associated username |
| Host | `host.name` | Affected hostname |
| Process | `process.name` | Triggering process |

### Aggregations
```python
es.search(
    index=".siem-signals-*",
    query={"bool": {"must": [...]}},
    aggs={
        "by_severity": {"terms": {"field": "signal.rule.severity", "size": 10}},
        "by_rule": {"terms": {"field": "signal.rule.name.keyword", "size": 20}},
        "by_host": {"terms": {"field": "host.name.keyword", "size": 20}}
    },
    size=0
)
```

## Alert Status Management

### Update Alert Status
```python
es.update(
    index=".siem-signals-default-000001",
    id="alert_doc_id",
    body={"doc": {"signal": {"status": "closed"}}}
)
```

## Triage Prioritization

### Severity Priority
1. Critical (risk score 90-100)
2. High (risk score 70-89)
3. Medium (risk score 40-69)
4. Low (risk score 0-39)

### Alert Clustering
Alerts from the same host within a time window are grouped as potential incidents. Three or more alerts from the same host suggest a multi-stage attack.

## Elastic Security API

### List Detection Rules
```
GET /api/detection_engine/rules/_find?per_page=100
```

### Get Rule Execution Status
```
GET /api/detection_engine/rules/_find_statuses
```

## Output Schema

```json
{
  "report": "elastic_siem_alert_triage",
  "total_open_alerts": 45,
  "severity_summary": {"critical": 3, "high": 12, "medium": 20, "low": 10},
  "alert_clusters": [{"host": "web01", "alert_count": 5, "max_severity": "high"}],
  "aggregations": {"by_severity": [{"key": "high", "count": 12}]}
}
```

## CLI Usage

```bash
python agent.py --host https://elastic:9200 --api-key "key" --hours 24 --output report.json
```
