# Workflows - Threat Intelligence Enrichment in Splunk

## TI Feed Integration Workflow

```
1. Identify Relevant TI Sources
   - Commercial feeds (Recorded Future, Mandiant)
   - Open source (OTX, AbuseIPDB, VirusTotal)
   - Industry ISACs
   - Internal threat lists
   |
   v
2. Configure Modular Inputs
   - Set polling intervals
   - Configure authentication
   - Map feed fields to Splunk schema
   |
   v
3. Normalize to KV Store
   - Parse raw feed data
   - Map to standard field names
   - Set confidence scores
   - Add source attribution
   |
   v
4. Create Lookup Definitions
   - Define transforms.conf entries
   - Set field mappings
   - Enable automatic lookups where appropriate
   |
   v
5. Build Correlation Searches
   - Match events against IOC lookups
   - Add asset/identity enrichment
   - Set severity based on confidence
   |
   v
6. Monitor and Maintain
   - Track feed freshness
   - Remove stale indicators
   - Measure hit rates per source
```

## IOC Lifecycle Management

```
Ingestion --> Validation --> Active Use --> Aging --> Expiration --> Removal
    |              |            |            |           |
    v              v            v            v           v
  Raw feeds    Dedup and    Correlation   Reduce      Archive
  parsed       confidence   matching     confidence   or delete
               scoring                   weighting
```

## Feed Quality Assessment

| Metric | Good | Warning | Critical |
|---|---|---|---|
| Feed latency | < 1 hour | 1-24 hours | > 24 hours |
| False positive rate | < 5% | 5-15% | > 15% |
| Hit rate | > 1% | 0.1-1% | < 0.1% |
| Coverage overlap | < 30% | 30-60% | > 60% |
| Indicator freshness | < 7 days | 7-30 days | > 30 days |
