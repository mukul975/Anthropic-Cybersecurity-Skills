# API Reference: Building Incident Response Dashboard

## splunk-sdk (splunklib)

```python
import splunklib.client as client
import splunklib.results as results

service = client.connect(host="localhost", port=8089,
                         username="admin", password="changeme")

# Run a blocking search
job = service.jobs.create(
    'search index=notable | stats count by urgency',
    earliest_time="-24h", latest_time="now", exec_mode="blocking"
)
for result in results.JSONResultsReader(job.results(output_mode="json")):
    print(result)

# Create a saved search (dashboard panel)
service.saved_searches.create("IR_Affected_Systems", search="""
    search index=notable incident_id="IR-*"
    | stats count by dest, urgency | sort - count
""")
```

## Key SPL Patterns for IR Dashboards

```spl
--- Incident summary single-value panels
| makeresults | eval status="CONTAINMENT", affected=7, contained=5

--- SOC Metrics (MTTD / MTTR)
index=notable status_label="Resolved*"
| eval mttr_hours = round((status_end - _time) / 3600, 1)
| stats avg(mttr_hours) AS avg_mttr by urgency

--- Analyst workload
index=notable earliest=-7d | stats count by owner | sort - count

--- IOC spread tracking
index=* (src_ip IN ("1.2.3.4") OR dest="evil.com")
| timechart span=1h count by sourcetype

--- Alert disposition
index=notable status_label="Closed*"
| stats count by disposition
| eventstats sum(count) AS total
| eval pct = round(count/total*100, 1)
```

## Dashboard Studio (Splunk v2)

```xml
<dashboard version="2" theme="dark">
  <label>IR Dashboard</label>
  <row>
    <panel><title>Affected Systems</title>
      <table><search><query>| inputlookup ir_systems.csv</query></search></table>
    </panel>
  </row>
</dashboard>
```

## TheHive API (Case Tracking)

```python
import requests
headers = {"Authorization": "Bearer <api_key>"}
# List open cases
resp = requests.get("http://thehive:9000/api/case",
    headers=headers, params={"range": "0-50", "sort": "-startDate"})
```

### References

- splunk-sdk-python: https://github.com/splunk/splunk-sdk-python
- Splunk Dashboard Studio: https://docs.splunk.com/Documentation/DashboardStudio
- TheHive API: https://docs.strangebee.com/thehive/api-docs/
