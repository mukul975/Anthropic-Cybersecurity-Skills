# API Reference: Threat Intelligence Platform

## STIX 2.1 Indicator Object
```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid5>",
  "created": "2025-01-15T10:00:00.000Z",
  "modified": "2025-01-15T10:00:00.000Z",
  "name": "Malicious IP",
  "pattern": "[ipv4-addr:value = '198.51.100.42']",
  "pattern_type": "stix",
  "valid_from": "2025-01-15T10:00:00.000Z",
  "confidence": 85,
  "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"]
}
```

## TLP Marking Definition IDs (STIX 2.1)
| TLP Level | STIX Marking Definition ID |
|-----------|---------------------------|
| TLP:CLEAR | marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9 |
| TLP:GREEN | marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da |
| TLP:AMBER | marking-definition--f88d31f6-486f-44da-b317-01333bde0b82 |
| TLP:AMBER+STRICT | marking-definition--826578e1-40a3-4b46-a8d8-b9931fdd750e |
| TLP:RED | marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed |

## TAXII 2.1 Endpoints
```bash
# Discovery
curl https://taxii.server.com/taxii2/

# Collections
curl https://taxii.server.com/taxii2/collections/

# Get objects from collection
curl "https://taxii.server.com/taxii2/collections/{id}/objects?type=indicator"

# Add objects
curl -X POST "https://taxii.server.com/taxii2/collections/{id}/objects" \
  -H "Content-Type: application/stix+json;version=2.1" \
  -d @bundle.json
```

## OpenCTI GraphQL API
```graphql
mutation {
  indicatorAdd(input: {
    name: "Malicious IP"
    pattern: "[ipv4-addr:value = '198.51.100.42']"
    pattern_type: "stix"
    x_opencti_score: 80
  }) {
    id
    standard_id
  }
}
```

## MISP REST API
```bash
# Add attribute
curl -X POST "https://misp/attributes/add/EVENT_ID" \
  -H "Authorization: MISP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"ip-dst","value":"198.51.100.42","category":"Network activity","to_ids":true}'
```
