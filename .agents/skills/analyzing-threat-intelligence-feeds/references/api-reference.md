# API Reference: Analyzing Threat Intelligence Feeds

## taxii2-client

### Server Discovery

```python
from taxii2client.v21 import Server

server = Server("https://cti.example.com/taxii2/", user="u", password="p")
for api_root in server.api_roots:
    for col in api_root.collections:
        print(col.id, col.title)
```

### Fetch Indicators from Collection

```python
from taxii2client.v21 import Collection, as_pages

collection = Collection(
    "https://cti.example.com/taxii2/collections/abc123/",
    user="u", password="p"
)
for bundle in as_pages(collection.get_objects, per_request=100):
    for obj in bundle.get("objects", []):
        if obj["type"] == "indicator":
            print(obj["pattern"])
```

### Push Indicators

```python
collection.add_objects(stix_bundle_json)
```

## stix2 (Python Library)

### Create Indicator

```python
from stix2 import Indicator

indicator = Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '1.2.3.4']",
    pattern_type="stix",
    valid_from="2025-01-01T00:00:00Z",
    confidence=85,
)
```

### Create Bundle and Serialize

```python
from stix2 import Bundle
bundle = Bundle(objects=[indicator])
print(bundle.serialize(pretty=True))
```

### MemoryStore for Querying

```python
from stix2 import MemoryStore, Filter
store = MemoryStore(stix_data=bundle)
results = store.query([Filter("type", "=", "indicator")])
```

## STIX 2.1 Pattern Syntax

| IOC Type | Pattern |
|----------|---------|
| IPv4 | `[ipv4-addr:value = '1.2.3.4']` |
| Domain | `[domain-name:value = 'evil.com']` |
| SHA-256 | `[file:hashes.'SHA-256' = 'abc...']` |
| URL | `[url:value = 'http://evil.com/payload']` |
| Email | `[email-addr:value = 'phish@evil.com']` |

## TAXII 2.1 HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/taxii2/` | GET | Server discovery |
| `/{api-root}/collections/` | GET | List collections |
| `/{api-root}/collections/{id}/objects/` | GET | Get STIX objects |
| `/{api-root}/collections/{id}/objects/` | POST | Add STIX objects |

### References

- taxii2-client: https://pypi.org/project/taxii2-client/
- stix2 library: https://pypi.org/project/stix2/
- STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- TAXII 2.1 spec: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
