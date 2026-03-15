# API Reference: Security Information Sharing with STIX 2.1

## stix2 Python Library
```bash
pip install stix2 taxii2-client
```

### Create Objects
```python
from stix2 import Indicator, Malware, Relationship, Bundle, Identity

identity = Identity(name="My SOC", identity_class="organization")

indicator = Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '198.51.100.42']",
    pattern_type="stix",
    valid_from="2025-01-01T00:00:00Z",
    created_by_ref=identity.id,
)

malware = Malware(name="EvilRAT", malware_types=["trojan"], is_family=True)

rel = Relationship(source_ref=indicator.id, target_ref=malware.id,
                   relationship_type="indicates")

bundle = Bundle(objects=[identity, indicator, malware, rel])
print(bundle.serialize(pretty=True))
```

### Validate and Parse
```python
import stix2

parsed = stix2.parse(json_string, allow_custom=True)
print(parsed.type, len(parsed.objects))
```

## STIX 2.1 Object Types
| Type | Description |
|------|------------|
| indicator | IOC with STIX pattern |
| malware | Malware family/sample |
| campaign | Named threat campaign |
| threat-actor | Threat group |
| attack-pattern | TTP (ATT&CK technique) |
| relationship | Link between objects |
| sighting | Observation of indicator |
| identity | Organization/individual |

## TAXII 2.1 Publishing
```python
from taxii2client.v21 import Collection

collection = Collection(
    "https://taxii.server.com/taxii2/collections/abc-123/",
    user="api_user", password="api_pass"
)
collection.add_objects(bundle.serialize())
```

## TLP Marking Definitions
| TLP | stix2 Constant |
|-----|---------------|
| TLP:CLEAR | stix2.TLP_WHITE |
| TLP:GREEN | stix2.TLP_GREEN |
| TLP:AMBER | stix2.TLP_AMBER |
| TLP:RED | stix2.TLP_RED |

## STIX Pattern Examples
| Type | Pattern |
|------|---------|
| IPv4 | `[ipv4-addr:value = '1.2.3.4']` |
| Domain | `[domain-name:value = 'evil.com']` |
| SHA-256 | `[file:hashes.'SHA-256' = 'abc...']` |
| URL | `[url:value = 'https://evil.com/mal']` |
| Email | `[email-addr:value = 'bad@evil.com']` |
