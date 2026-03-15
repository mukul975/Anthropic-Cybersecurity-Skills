# STIX/TAXII Feed Integration Workflows

## Workflow 1: TAXII Feed Consumption

```
[TAXII Discovery] --> [API Root Enumeration] --> [Collection Selection] --> [Object Polling]
                                                                                 |
                                                                                 v
                                                                     [STIX Parsing] --> [IOC Extraction]
                                                                                              |
                                                                                              v
                                                                                    [SIEM/TIP Ingestion]
```

### Steps:
1. **Discovery**: Query TAXII server discovery endpoint for available API roots
2. **Root Enumeration**: List available API roots and their supported features
3. **Collection Listing**: Enumerate collections with read/write permissions
4. **Incremental Polling**: Fetch new objects using added_after timestamp filter
5. **STIX Parsing**: Deserialize JSON into typed STIX objects
6. **IOC Extraction**: Extract indicators, observables, and relationships
7. **Platform Ingestion**: Push to SIEM, MISP, or OpenCTI

## Workflow 2: STIX Bundle Production

```
[IOC Sources] --> [Normalization] --> [STIX Object Creation] --> [Bundle Assembly]
                                                                        |
                                                                        v
                                                              [TAXII Publication]
```

### Steps:
1. **Source Collection**: Gather IOCs from internal analysis, feeds, incident response
2. **Normalization**: Standardize IOC formats and remove duplicates
3. **Object Creation**: Create STIX Indicators, Observables, and Relationships
4. **TLP Marking**: Apply appropriate TLP marking definitions
5. **Bundle Assembly**: Package objects into STIX 2.1 bundles
6. **TAXII Push**: POST bundles to writable TAXII collections

## Workflow 3: Multi-Feed Aggregation

```
[TAXII Feed A] --+
                  |--> [Deduplication] --> [Correlation] --> [Unified Store]
[TAXII Feed B] --+                                                |
                  |                                                v
[STIX File C] ---+                                      [Dashboard/Alerts]
```

### Steps:
1. **Feed Registration**: Configure multiple TAXII and file-based STIX sources
2. **Parallel Polling**: Poll all feeds concurrently with rate limiting
3. **Deduplication**: Remove duplicate objects by STIX ID and modified timestamp
4. **Correlation**: Link related objects across feeds via relationships
5. **Unified Storage**: Store in MemoryStore, FileSystemStore, or database-backed store
6. **Output**: Generate alerts, dashboards, or exports for downstream consumers
