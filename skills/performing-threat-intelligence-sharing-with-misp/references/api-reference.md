# MISP / PyMISP API Reference

## Installation

```bash
pip install pymisp
```

## Connection Setup

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP(
    url="https://misp.example.com",
    key="YOUR_API_KEY",
    ssl=True
)
```

## Core PyMISP Methods

| Method | Description |
|--------|-------------|
| `misp.add_event(event)` | Create new event |
| `misp.update_event(event)` | Update existing event |
| `misp.publish(event)` | Publish event for sharing |
| `misp.delete_event(event_id)` | Delete an event |
| `misp.search(controller, value, type_attribute)` | Search events/attributes |
| `misp.get_event(event_id)` | Retrieve single event |
| `misp.add_tag(event, tag)` | Add tag to event |
| `misp.search_index(published=True)` | Search event index |

## Creating Events

```python
event = MISPEvent()
event.info = "APT Campaign - Phishing IOCs"
event.distribution = 1        # 0=Org, 1=Community, 2=Connected, 3=All
event.threat_level_id = 2     # 1=High, 2=Medium, 3=Low, 4=Undefined
event.analysis = 0            # 0=Initial, 1=Ongoing, 2=Complete

event.add_attribute("ip-dst", "203.0.113.50", to_ids=True, comment="C2 server")
event.add_attribute("domain", "evil.example.com", to_ids=True)
event.add_attribute("sha256", "a1b2c3d4...", category="Payload delivery")
event.add_tag("tlp:amber")
event.add_tag("mitre-attack-pattern:T1566 - Phishing")

result = misp.add_event(event)
```

## Searching Intelligence

```python
# Search by attribute value
results = misp.search(controller="attributes", value="203.0.113.50", type_attribute="ip-dst")

# Search events by date range
results = misp.search(controller="events", date_from="2025-01-01", date_to="2025-12-31")

# Search with tags
results = misp.search(controller="events", tags=["tlp:white", "ransomware"])
```

## MISP Attribute Types

| Type | Example | Category |
|------|---------|----------|
| `ip-dst` | `203.0.113.50` | Network activity |
| `domain` | `evil.example.com` | Network activity |
| `url` | `https://evil.com/payload` | Network activity |
| `sha256` | `a1b2c3...` | Payload delivery |
| `md5` | `d41d8c...` | Payload delivery |
| `email-src` | `attacker@evil.com` | Payload delivery |
| `filename` | `malware.exe` | Payload delivery |
| `regkey` | `HKLM\...\Run\evil` | Persistence mechanism |

## Distribution Levels

- `0` - Your organisation only
- `1` - This community only
- `2` - Connected communities
- `3` - All communities
- `4` - Sharing group

## CLI Usage

```bash
python agent.py --input events.json --output report.json
python agent.py --input events.json --misp-url https://misp.example.com --api-key KEY
```

## References

- PyMISP Docs: https://pymisp.readthedocs.io/
- PyMISP GitHub: https://github.com/MISP/PyMISP
- MISP REST API: https://www.circl.lu/doc/misp/automation/
