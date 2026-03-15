# API Reference: IOC Enrichment Pipeline with OpenCTI

## pycti — OpenCTI Python Client

### Installation
```bash
pip install pycti
```

### Client Initialization
```python
from pycti import OpenCTIApiClient

client = OpenCTIApiClient(
    url="http://localhost:8080",
    token=os.environ.get("OPENCTI_TOKEN", "")
)
```

### Indicator Operations
```python
# List indicators with filter
filters = {
    "mode": "and",
    "filters": [{"key": "value", "values": ["198.51.100.42"]}],
    "filterGroups": []
}
indicators = client.indicator.list(filters=filters)

# Create indicator
client.indicator.create(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '198.51.100.42']",
    pattern_type="stix",
    x_opencti_score=80,
    valid_from="2025-01-01T00:00:00Z"
)
```

### Observable Operations
```python
# Search observables
obs = client.stix_cyber_observable.list(filters=filters)

# Create observable
client.stix_cyber_observable.create(
    observableData={
        "type": "ipv4-addr",
        "value": "198.51.100.42"
    }
)
```

### Relationship Queries
```python
# Get relationships from entity
rels = client.stix_core_relationship.list(
    filters={
        "mode": "and",
        "filters": [{"key": "fromId", "values": [entity_id]}],
        "filterGroups": []
    }
)
```

## OpenCTI GraphQL API

### Endpoint
```
POST /graphql
Authorization: Bearer <token>
Content-Type: application/json
```

### Example Query
```graphql
query {
  indicators(filters: {
    mode: and
    filters: [{ key: "value", values: ["198.51.100.42"] }]
    filterGroups: []
  }) {
    edges {
      node {
        id
        pattern
        x_opencti_score
        createdBy { name }
        objectLabel { value }
      }
    }
  }
}
```

## STIX Indicator Patterns
| Type | STIX Pattern |
|------|-------------|
| IPv4 |  |
| Domain |  |
| URL |  |
| SHA-256 |  |
| MD5 |  |
| Email |  |
