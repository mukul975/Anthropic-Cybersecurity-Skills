# API Reference: MISP Threat Landscape Analysis

## PyMISP Connection
```python
from pymisp import PyMISP
misp = PyMISP(url, api_key, ssl=True)
```

## Event Search
```python
events = misp.search(date_from="2025-01-01", pythonify=True)
```
| Parameter | Description |
|-----------|-------------|
| `date_from` | Start date (YYYY-MM-DD) |
| `date_to` | End date |
| `tags` | Filter by tags |
| `threat_level_id` | 1=High, 2=Medium, 3=Low, 4=Undefined |
| `published` | True/False |
| `pythonify` | Return MISPEvent objects |

## Event Object Fields
| Field | Description |
|-------|-------------|
| `id` | Event ID |
| `date` | Event date |
| `threat_level_id` | 1-4 severity level |
| `analysis` | 0=Initial, 1=Ongoing, 2=Completed |
| `info` | Event description |
| `Attribute` | List of IOC attributes |
| `Tag` | List of tags |
| `Orgc` | Contributing organization |

## Attribute Types
| Type | Example |
|------|---------|
| `ip-dst` | Destination IP address |
| `ip-src` | Source IP address |
| `domain` | Domain name |
| `hostname` | FQDN |
| `url` | Full URL |
| `md5` / `sha1` / `sha256` | File hashes |
| `email-src` | Sender email |
| `filename` | Malicious filename |
| `mutex` | Mutex name |
| `regkey` | Registry key |

## Galaxy Tag Prefixes
| Prefix | Content |
|--------|---------|
| `misp-galaxy:mitre-attack-pattern=` | MITRE ATT&CK techniques |
| `misp-galaxy:threat-actor=` | Threat actor groups |
| `misp-galaxy:malpedia=` | Malware families |
| `misp-galaxy:sector=` | Target sectors |
| `misp-galaxy:country=` | Target countries |

## Statistics API
```python
misp.get_community_id()
misp.user_statistics()
misp.attributes_statistics(context="type")
misp.attributes_statistics(context="category")
misp.tags_statistics()
```
