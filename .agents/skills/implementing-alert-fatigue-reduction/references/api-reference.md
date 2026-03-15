# API Reference: Implementing Alert Fatigue Reduction

## Libraries

### splunk-sdk (Splunk SDK for Python)
- **Install**: `pip install splunk-sdk`
- **Docs**: https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/
- `splunklib.client.connect(host, port, username, password)` -- Connect to Splunk
- `service.jobs.create(query)` -- Execute a search query
- `job.is_done()` -- Check if search job completed
- `job.results(output_mode="json")` -- Retrieve results in JSON format
- `splunklib.results.JSONResultsReader(stream)` -- Parse JSON results

### Splunk ES Notable Events API
- **Endpoint**: `/services/notable_update`
- **Methods**: POST to update notable event status
- **Fields**: `status`, `urgency`, `owner`, `comment`, `ruleUIDs`
- **Status values**: `0` (Unassigned), `1` (New), `2` (In Progress), `5` (Resolved)

## Key SPL Queries

| Purpose | Key Functions |
|---------|--------------|
| Alert volume analysis | `stats count by rule_name`, `eval fp_rate` |
| Risk-based alerting | `collect index=risk`, `eval risk_score` |
| Alert consolidation | `dedup src, rule_name span=300` |
| Capacity calculation | `bin _time span=1d`, `stats avg(daily_alerts)` |
| Tiered routing | `eval routing = case(urgency, ...)` |

## Risk-Based Alerting (RBA) Framework
- Risk contributions replace individual alerts
- `index=risk` stores cumulative risk scores per entity
- Threshold alert fires only when `total_risk >= 75`
- Typical risk score ranges: 5 (low) to 50 (critical)

## Metrics Targets

| Metric | Target |
|--------|--------|
| False Positive Rate | < 30% per production rule |
| Alerts/Analyst/Shift | 40-60 (manageable range) |
| Signal-to-Noise Ratio | > 1.0 |
| MTTD | Under 15 minutes for critical |
| MTTR | Under 4 hours for high severity |

## External References
- Splunk ES RBA Docs: https://docs.splunk.com/Documentation/ES/latest/Admin/RBA
- Splunk SDK Python: https://github.com/splunk/splunk-sdk-python
- MITRE ATT&CK Detection: https://attack.mitre.org/resources/
