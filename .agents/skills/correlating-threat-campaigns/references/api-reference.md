# Threat Campaign Correlation API Reference

## MISP REST API

```bash
# Search attributes
curl -X POST "https://misp.example.com/attributes/restSearch" \
  -H "Authorization: YOUR_API_KEY" -H "Content-Type: application/json" \
  -d '{"type": "ip-src", "value": "185.220.101.42"}'

# Search events by tag
curl -X POST "https://misp.example.com/events/restSearch" \
  -H "Authorization: YOUR_API_KEY" -H "Content-Type: application/json" \
  -d '{"tags": ["apt28", "fancy-bear"], "from": "2024-01-01"}'

# Get event with correlations
curl "https://misp.example.com/events/view/1234" \
  -H "Authorization: YOUR_API_KEY" -H "Accept: application/json"

# Add attribute to event
curl -X POST "https://misp.example.com/attributes/add/1234" \
  -H "Authorization: YOUR_API_KEY" -H "Content-Type: application/json" \
  -d '{"type": "ip-dst", "value": "203.0.113.50", "category": "Network activity", "to_ids": true}'
```

## MISP Correlation Engine

| Correlation Type | Description |
|-----------------|-------------|
| Attribute match | Same value in multiple events |
| CIDR overlap | IPs in same /24 or /16 subnet |
| Fuzzy hash (ssdeep) | Similar malware samples |
| Over-correlation | Common values excluded (CDN IPs) |

## OpenCTI GraphQL API

```graphql
# Query campaign relationships
query {
  campaign(id: "campaign-uuid") {
    name
    first_seen
    last_seen
    objectsOfRelationship(relationship_type: "uses") {
      edges { node { ... on Malware { name } } }
    }
    objectsOfRelationship(relationship_type: "attributed-to") {
      edges { node { ... on IntrusionSet { name aliases } } }
    }
  }
}
```

## STIX 2.1 Campaign Object

```json
{
  "type": "campaign",
  "spec_version": "2.1",
  "id": "campaign--uuid",
  "name": "Operation ShadowStrike",
  "first_seen": "2024-01-15T00:00:00Z",
  "last_seen": "2024-06-30T00:00:00Z",
  "objective": "Data exfiltration from financial sector"
}
```

## STIX Relationship Types

| Type | Source | Target |
|------|--------|--------|
| `attributed-to` | Campaign | Threat Actor |
| `uses` | Intrusion Set | Malware / Tool |
| `targets` | Campaign | Identity / Sector |
| `indicates` | Indicator | Malware |
| `related-to` | Any | Any |
