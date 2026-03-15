# API Reference: Triaging Security Alerts in Splunk

## splunklib (Splunk SDK for Python)

### Installation
```bash
pip install splunk-sdk
```

### Connection
```python
import splunklib.client as client
service = client.connect(host="localhost", port=8089,
                         username="admin", password="password")
```

### Running Searches
```python
# Blocking search (wait for results)
job = service.jobs.create(query, exec_mode="blocking")

# Parse results
import splunklib.results as results
for result in results.JSONResultsReader(job.results(output_mode="json")):
    if isinstance(result, dict):
        print(result)
```

### Search Parameters
| Parameter | Description |
|-----------|-------------|
| `exec_mode` | `blocking` (wait) or `normal` (async) |
| `earliest_time` | Search time range start (e.g., `-24h`) |
| `latest_time` | Search time range end (e.g., `now`) |
| `output_mode` | `json`, `xml`, or `csv` |

## Key SPL Commands for Triage

| Command | Purpose |
|---------|---------|
| `` `notable` `` | Macro to access ES notable events |
| `lookup asset_lookup_by_cidr` | Enrich with asset information |
| `lookup identity_lookup_expanded` | Enrich with identity context |
| `lookup threat_intel_by_ip` | Check IP against threat feeds |
| `tstats` | Fast datamodel statistics |
| `sendalert update_notable_event` | Update notable event status |

## Notable Event Status Values
| Value | Status |
|-------|--------|
| 0 | Unassigned |
| 1 | New |
| 2 | In Progress |
| 3 | Pending |
| 4 | Resolved |
| 5 | Closed |

## Disposition Categories
| Disposition | Criteria |
|-------------|----------|
| True Positive | Confirmed malicious activity |
| Benign True Positive | Alert correct but activity authorized |
| False Positive | Benign behavior matched detection logic |
| Undetermined | Insufficient data to classify |

## References
- Splunk SDK for Python: https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/
- Splunk ES notable events: https://docs.splunk.com/Documentation/ES/latest/Admin/Managenotableevents
- SPL reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/
