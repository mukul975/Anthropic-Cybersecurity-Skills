# API Reference: Collecting Threat Intelligence with MISP

## PyMISP Installation
```bash
pip install pymisp
```

## Client Initialization
```python
from pymisp import PyMISP

misp = PyMISP(
    url="https://misp.example.org",
    key=os.environ["MISP_API_KEY"],
    ssl=True
)
```

## Event Search
```python
# By tags
events = misp.search("events", tags=["tlp:white", "type:OSINT"], pythonify=True)

# By date range
events = misp.search("events", date_from="2025-01-01", date_to="2025-01-31", pythonify=True)

# Published only
events = misp.search("events", published=True, limit=100, pythonify=True)
```

## Attribute Search
```python
# By type
attrs = misp.search("attributes", type_attribute="ip-dst", to_ids=True, pythonify=True)

# By event
attrs = misp.search("attributes", eventid=42, pythonify=True)

# By value
attrs = misp.search("attributes", value="198.51.100.42", pythonify=True)
```

## REST API (curl)
```bash
# Search events
curl -X POST "https://misp/events/restSearch" \
  -H "Authorization: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"tags":["tlp:white"],"limit":50}'

# Get event
curl -H "Authorization: $KEY" "https://misp/events/view/42"

# STIX 2 export
curl -H "Authorization: $KEY" "https://misp/events/restSearch/stix2"
```

## Common Attribute Types
| Type | Category | Example |
|------|----------|---------|
| ip-dst | Network activity | 198.51.100.42 |
| domain | Network activity | evil.example.com |
| url | Network activity | https://evil.com/mal |
| sha256 | Payload delivery | a1b2c3... |
| md5 | Payload delivery | d41d8c... |
| email-src | Payload delivery | attacker@evil.com |
| filename | Payload delivery | malware.exe |

## Feed Management
```python
# List feeds
feeds = misp.feeds()

# Enable feed
misp.enable_feed(feed_id=1)

# Fetch and cache
misp.fetch_feed(feed_id=1)
misp.cache_feeds()
```
