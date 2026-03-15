# API Reference: Analyzing Security Logs with Splunk

## splunk-sdk (splunklib)

### Connection

```python
import splunklib.client as client

service = client.connect(
    host="splunk.example.com",
    port=8089,
    username="admin",
    password="secret",
    autologin=True,
)
```

### Running Searches

```python
import splunklib.results as results

# Blocking (synchronous) search
job = service.jobs.create(
    "search index=windows EventCode=4625 | stats count by src_ip",
    **{"earliest_time": "-24h", "latest_time": "now", "exec_mode": "blocking"}
)

# Read results as JSON
reader = results.JSONResultsReader(job.results(output_mode="json"))
for row in reader:
    if isinstance(row, dict):
        print(row)
job.cancel()
```

### Oneshot Search (Simple Queries)

```python
result_stream = service.jobs.oneshot(
    "search index=windows EventCode=4624 | head 10",
    earliest_time="-1h",
    output_mode="json",
)
reader = results.JSONResultsReader(result_stream)
```

### Saved Searches

```python
# List saved searches
for saved in service.saved_searches:
    print(saved.name)

# Run a saved search
saved_search = service.saved_searches["My Alert"]
job = saved_search.dispatch()
```

### KV Store Lookups

```python
collection = service.kvstore["threat_intel_iocs"]
# Insert record
collection.data.insert(json.dumps({"ip": "1.2.3.4", "threat": "C2"}))
# Query records
records = collection.data.query(query=json.dumps({"threat": "C2"}))
```

### Key SPL Patterns for Security Analysis

| Pattern | SPL |
|---------|-----|
| Failed logons | `index=windows EventCode=4625 \| stats count by src_ip` |
| Lateral movement | `index=windows EventCode=4624 Logon_Type=3 \| stats dc(host) by src_ip` |
| Process creation | `index=sysmon EventCode=1 \| table _time, Image, CommandLine` |
| C2 beaconing | `index=proxy \| timechart span=1m count by dest_ip` |
| DNS tunneling | `index=dns \| stats count, avg(len(query)) by domain` |

### Splunk REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/services/search/jobs` | POST | Create a new search job |
| `/services/search/jobs/{sid}/results` | GET | Retrieve search results |
| `/services/saved/searches` | GET | List saved searches |
| `/services/data/indexes` | GET | List available indexes |
| `/services/authentication/users` | GET | List Splunk users |

### References

- splunk-sdk PyPI: https://pypi.org/project/splunk-sdk/
- Splunk REST API docs: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF
- Splunk SDK for Python: https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/
