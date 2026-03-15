# API Reference: MISP Threat Intelligence Platform

## PyMISP Constructor
```python
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag
misp = PyMISP(url, key, ssl=True, debug=False, proxies=None,
              cert=None, auth=None, tool='', timeout=None)
```

## Core Methods
```python
misp.add_event(event, pythonify=False, metadata=False)
misp.get_event(event_id, pythonify=False)
misp.update_event(event, pythonify=False)
misp.add_attribute(event_id, attribute, pythonify=False)
misp.update_attribute(attribute, pythonify=False)
misp.search(value=None, type_attribute=None, category=None,
            org=None, tags=None, pythonify=False)
misp.add_tag(tag, pythonify=False)
misp.get_stix_event(event_id)
```

## MISPEvent Object
```python
event = MISPEvent()
event.info = "Event description"
event.threat_level_id = 2  # 1=High, 2=Medium, 3=Low, 4=Undefined
event.distribution = 1     # 0=Org, 1=Community, 2=Connected, 3=All
event.analysis = 0          # 0=Initial, 1=Ongoing, 2=Complete
event.add_attribute("ip-dst", "1.2.3.4", to_ids=True)
event.add_tag(tag)
```

## MISPAttribute Object
```python
attr = MISPAttribute()
attr.type = "ip-dst"  # ip-dst, domain, url, sha256, md5, email-src
attr.value = "1.2.3.4"
attr.to_ids = True
attr.category = "Network activity"
attr.comment = "C2 server"
```

## Feed APIs
| Feed | Endpoint | Method |
|------|----------|--------|
| URLhaus | `https://urlhaus-api.abuse.ch/api/v1/urls/recent/limit/N/` | POST |
| Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json` | GET |
| MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | POST (query=get_info) |

## VirusTotal v3 - IP Enrichment
```
GET /api/v3/ip_addresses/{ip}
Header: x-apikey: <key>
Response: data.attributes.last_analysis_stats.malicious
```
