# API Reference: Detecting Insider Threat with UEBA

## Elasticsearch Aggregation Queries

### Per-User Daily Activity Baseline
```json
{
  "aggs": {
    "users": {
      "terms": {"field": "user.name", "size": 5000},
      "aggs": {
        "daily_events": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}},
        "unique_hosts": {"cardinality": {"field": "host.name"}},
        "data_volume": {"sum": {"field": "bytes_transferred"}}
      }
    }
  }
}
```

### Anomaly Detection (Z-Score > 3)
```python
from elasticsearch import Elasticsearch
es = Elasticsearch(["https://localhost:9200"], api_key="base64key")
result = es.search(index="logs-*", body=query)
z_score = (current - baseline_avg) / baseline_std
```

## Insider Threat Indicators

| Indicator | Detection Method | Severity |
|-----------|-----------------|----------|
| Activity spike | Z-score > 3 standard deviations | High |
| Data exfiltration | Volume > 5x daily average | Critical |
| New host access | Unique hosts > 2x baseline | High |
| Off-hours activity | Login outside 06:00-22:00 | Medium |
| Peer group outlier | Activity > 3x peer average | Medium |
| Privilege escalation | New admin role assignment | Critical |
| Resignation + download | HR flag + high data volume | Critical |

## Elasticsearch Python Client

```bash
pip install elasticsearch>=8.0
```

| Method | Description |
|--------|-------------|
| `es.search(index, body)` | Execute aggregation query |
| `es.indices.get_alias("logs-*")` | List matching indices |
| `es.count(index)` | Get document count |

## Risk Scoring Model

| Score Range | Risk Level | Action |
|-------------|------------|--------|
| 0 - 30 | Low | No action |
| 31 - 60 | Medium | Monitor |
| 61 - 80 | High | SOC investigation |
| 81 - 100 | Critical | Immediate response |

## MITRE ATT&CK Insider Techniques

| Technique | ID | UEBA Detection |
|-----------|----|----------------|
| Data from Local System | T1005 | Volume anomaly on file servers |
| Exfiltration Over Web Service | T1567 | Cloud upload volume spike |
| Account Manipulation | T1098 | Unusual privilege changes |
| Valid Accounts | T1078 | Off-hours or location anomaly |

### References

- Elasticsearch Python Client: https://elasticsearch-py.readthedocs.io/
- MITRE Insider Threat: https://attack.mitre.org/techniques/T1078/
- NIST SP 800-53 AC-2: https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-2/
