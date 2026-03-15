# API Reference: Threat Feed Aggregation with MISP

## PyMISP Python Client

### Installation
```bash
pip install pymisp
```

### Client Initialization
```python
from pymisp import PyMISP

misp = PyMISP(
    url="https://misp.example.org",
    key=os.environ.get("MISP_API_KEY", ""),
    ssl=True
)
```

### Feed Management
```python
# List all feeds
feeds = misp.feeds()

# Enable a feed
misp.enable_feed(feed_id=1)

# Fetch feed data
misp.fetch_feed(feed_id=1)

# Cache feed locally
misp.cache_feeds()

# Add new feed
feed = misp.add_feed(
    name="Abuse.ch URLhaus",
    provider="abuse.ch",
    url="https://urlhaus.abuse.ch/downloads/csv_recent/",
    input_source="network",
    source_format="csv"
)
```

### Event Operations
```python
# Search events by tag
events = misp.search(tags=["tlp:white", "type:OSINT"])

# Get event attributes
event = misp.get_event(event_id=42)
for attr in event.Attribute:
    print(f"{attr.type}: {attr.value}")

# Add attribute to event
misp.add_attribute(event_id=42, type="ip-dst", value="198.51.100.1")
```

### STIX/TAXII Export
```bash
# STIX export via REST
curl -H "Authorization: $MISP_KEY" \
  "https://misp.example.org/events/restSearch/stix2"

# TAXII collection
curl "https://misp.example.org/taxii2/collections"
```

## Common Feed Sources
| Feed | URL | Format |
|------|-----|--------|
| Abuse.ch URLhaus | https://urlhaus.abuse.ch/downloads/csv_recent/ | CSV |
| Abuse.ch Feodo | https://feodotracker.abuse.ch/downloads/ipblocklist.csv | CSV |
| CIRCL OSINT | https://www.circl.lu/doc/misp/feed-osint/ | MISP |
| Botvrij.eu | https://www.botvrij.eu/data/feed-osint/ | MISP |
| PhishTank | https://data.phishtank.com/data/online-valid.json | JSON |

## Feed Configuration Fields
| Field | Description |
|-------|------------|
| name | Human-readable feed name |
| provider | Organization providing the feed |
| url | Feed URL or local path |
| input_source | "network" or "local" |
| source_format | "misp", "csv", "freetext", "stix" |
| enabled | Boolean to activate feed |
| distribution | 0=Org, 1=Community, 2=Connected, 3=All |
| delta_merge | Only import new/changed data |
