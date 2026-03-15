# API Reference: Implementing API Threat Protection with Apigee

## JSONThreatProtection Policy

```xml
<JSONThreatProtection name="JSON-Threat">
    <ObjectEntryCount>25</ObjectEntryCount>
    <ArrayElementCount>100</ArrayElementCount>
    <ContainerDepth>5</ContainerDepth>
    <StringValueLength>500</StringValueLength>
    <Source>request</Source>
</JSONThreatProtection>
```

## SpikeArrest Policy

```xml
<SpikeArrest name="Spike-Arrest">
    <Rate>30ps</Rate>
    <Identifier ref="request.header.x-api-key"/>
</SpikeArrest>
```

## RegularExpressionProtection

```xml
<RegularExpressionProtection name="Regex-Protect">
    <Source>request</Source>
    <QueryParam name="*">
        <Pattern>[\s]*((delete)|(exec)|(drop\s*table))</Pattern>
    </QueryParam>
</RegularExpressionProtection>
```

## Apigee Management API

```bash
# Deploy proxy revision
curl -X POST "https://apigee.googleapis.com/v1/organizations/{org}/environments/{env}/apis/{api}/revisions/{rev}/deployments" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)"

# List deployed proxies
curl "https://apigee.googleapis.com/v1/organizations/{org}/apis" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)"
```

## Recommended Policy Limits

| Setting | Recommended | Description |
|---------|-------------|-------------|
| ContainerDepth | 5 | JSON nesting depth |
| StringValueLength | 500 | Max string value |
| ObjectEntryCount | 25 | Max object keys |
| SpikeArrest Rate | 30ps | Requests per second |

### References

- Apigee Policies: https://cloud.google.com/apigee/docs/api-platform/reference/policies
- Apigee Security: https://cloud.google.com/apigee/docs/api-platform/security
