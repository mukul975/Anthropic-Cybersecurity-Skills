# Threat Intelligence Platform Evaluation API Reference

## MISP REST API

```bash
# Get version
curl "https://misp.example.com/servers/getVersion.json" \
  -H "Authorization: YOUR_API_KEY" -H "Accept: application/json"

# Search events
curl -X POST "https://misp.example.com/events/restSearch" \
  -H "Authorization: YOUR_API_KEY" -H "Content-Type: application/json" \
  -d '{"tags": ["apt28"], "limit": 50}'

# Export STIX 2.1
curl "https://misp.example.com/events/restSearch" \
  -H "Authorization: YOUR_API_KEY" -H "Accept: application/json" \
  -d '{"returnFormat": "stix2"}'

# Feed management
curl "https://misp.example.com/feeds/index.json" -H "Authorization: YOUR_API_KEY"
```

## OpenCTI GraphQL API

```graphql
# Get platform version
query { about { version } }

# Search indicators
query {
  indicators(filters: { key: "pattern_type", values: ["stix"] }) {
    edges { node { name pattern valid_from valid_until } }
  }
}

# Get campaigns
query {
  campaigns(first: 20, orderBy: created_at, orderMode: desc) {
    edges { node { name first_seen last_seen objectLabel { value } } }
  }
}
```

## ThreatConnect REST API

```bash
# List indicators
curl "https://api.threatconnect.com/v3/indicators" \
  -H "Authorization: TC <ACCESS_ID>:<HMAC_SIGNATURE>"

# Create indicator
curl -X POST "https://api.threatconnect.com/v3/indicators" \
  -H "Content-Type: application/json" \
  -d '{"type":"Host","hostName":"evil.example.com","rating":5,"confidence":80}'
```

## TAXII 2.1 API

```bash
# Discovery
curl https://taxii.example.com/taxii2/ -H "Accept: application/taxii+json;version=2.1"

# Get API roots
curl https://taxii.example.com/api1/ -H "Accept: application/taxii+json;version=2.1"

# List collections
curl https://taxii.example.com/api1/collections/ -H "Accept: application/taxii+json;version=2.1"

# Get objects from collection
curl "https://taxii.example.com/api1/collections/{id}/objects/" \
  -H "Accept: application/stix+json;version=2.1"
```

## TIP Evaluation Criteria Weights

| Category | Criterion | Weight |
|----------|-----------|--------|
| Core | STIX 2.1 support | 10 |
| Core | REST API | 9 |
| Core | TAXII server | 8 |
| Core | TLP enforcement | 8 |
| Integration | SIEM integration | 9 |
| Integration | Feed ingestion | 8 |
| Integration | EDR integration | 7 |
| Operations | Sharing (ISAC) | 7 |
| Operations | Analyst workflow | 7 |
| Operations | Reporting | 6 |

## Platform Comparison Matrix

| Feature | MISP | OpenCTI | ThreatConnect |
|---------|------|---------|---------------|
| License | Open Source | Open Source | Commercial |
| STIX 2.1 | Native | Native | Import/Export |
| TAXII 2.1 | Yes | Yes | Yes |
| ATT&CK | Plugin | Native | Module |
| Graph Viz | Basic | Advanced | Advanced |
| SOAR | API | Connectors | Playbooks |
