# API Reference: Building Automated Malware Submission Pipeline

## VirusTotal API v3

### File Lookup by Hash

```python
resp = requests.get(
    f"https://www.virustotal.com/api/v3/files/{sha256}",
    headers={"x-apikey": VT_KEY},
)
stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
```

### Submit File for Scanning

```python
resp = requests.post(
    "https://www.virustotal.com/api/v3/files",
    headers={"x-apikey": VT_KEY},
    files={"file": open(filepath, "rb")},
)
analysis_id = resp.json()["data"]["id"]
```

## MalwareBazaar API

```python
resp = requests.post(
    "https://mb-api.abuse.ch/api/v1/",
    data={"query": "get_info", "hash": sha256},
)
if resp.json()["query_status"] == "ok":
    entry = resp.json()["data"][0]
    print(entry["signature"], entry["tags"])
```

## Cuckoo Sandbox REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/tasks/create/file` | POST | Submit file for analysis |
| `/tasks/view/{id}` | GET | Check task status |
| `/tasks/report/{id}` | GET | Get analysis report |
| `/tasks/list` | GET | List all tasks |

```python
# Submit
resp = requests.post(
    f"{CUCKOO_URL}/tasks/create/file",
    files={"file": open(path, "rb")},
    data={"timeout": 300, "machine": "win10_x64"},
)
task_id = resp.json()["task_id"]

# Check status
resp = requests.get(f"{CUCKOO_URL}/tasks/view/{task_id}")
status = resp.json()["task"]["status"]  # "reported" when done
```

## Splunk HEC (HTTP Event Collector)

```python
requests.post(
    f"{SPLUNK_URL}/services/collector/event",
    headers={"Authorization": f"Splunk {TOKEN}"},
    json={"sourcetype": "malware_analysis", "event": report_data},
)
```

### References

- VirusTotal API: https://docs.virustotal.com/reference/overview
- MalwareBazaar: https://bazaar.abuse.ch/api/
- Cuckoo API: https://cuckoo.readthedocs.io/en/latest/usage/api/
- Splunk HEC: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
