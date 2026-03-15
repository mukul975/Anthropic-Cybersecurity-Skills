# MISP Threat Intelligence Collection Workflows

## Workflow 1: Automated Feed Collection Pipeline

```
[Community Feeds] --> [MISP Feed Manager] --> [Event Creation] --> [Correlation Engine]
     |                      |                       |                      |
     v                      v                       v                      v
- CIRCL OSINT        - Schedule fetch         - Auto-tag with       - Deduplicate
- Botvrij.eu         - Parse formats            TLP/PAP             - Cross-reference
- abuse.ch           - Validate IOCs          - Set distribution    - Cluster similar
- PhishTank          - Filter warninglists    - Publish/unpublish     events
```

### Steps:
1. **Feed Registration**: Add feeds via UI or PyMISP API with source_format, URL, and headers
2. **Scheduled Fetch**: Configure cron job or MISP scheduler to pull feeds at intervals
3. **Parsing and Validation**: MISP parses feed content, validates IOC formats, checks against warninglists
4. **Event Generation**: Each feed pull creates or updates events with parsed attributes
5. **Correlation**: MISP correlates new attributes against existing data, identifying overlaps
6. **Distribution**: Events are distributed based on TLP and sharing group configurations

## Workflow 2: Manual Intelligence Collection

```
[Analyst Report] --> [Manual Event Creation] --> [Attribute Addition] --> [Enrichment]
                                                                              |
                                                                              v
                                                                    [Galaxy Tagging]
                                                                              |
                                                                              v
                                                                    [Publication]
```

### Steps:
1. **Event Creation**: Create event with descriptive info, date, distribution, TLP tag
2. **IOC Entry**: Add attributes (IP, domain, hash, URL) with correct category and type
3. **Object Construction**: Group related attributes into MISP objects (file, domain-ip, email)
4. **Galaxy Linking**: Link event to MITRE ATT&CK techniques, threat actor clusters, malware families
5. **Enrichment**: Use MISP modules (VirusTotal, Shodan, CIRCL PassiveDNS) to enrich attributes
6. **Review and Publish**: Analyst reviews, sets to_ids flags, publishes for community sharing

## Workflow 3: TAXII Feed Integration

```
[TAXII Server] --> [TAXII Client] --> [STIX Parser] --> [MISP Import] --> [Correlation]
```

### Steps:
1. **Discovery**: Query TAXII server discovery endpoint for available API roots
2. **Collection Enumeration**: List available collections and their metadata
3. **Object Retrieval**: Fetch STIX 2.1 objects from collections with pagination
4. **STIX-to-MISP Mapping**: Map STIX Indicator, Malware, Threat Actor to MISP event/attributes
5. **Import**: Create MISP events from STIX bundles
6. **Correlation**: Run correlation against existing MISP data

## Workflow 4: Instance Synchronization

```
[MISP Instance A] <--sync--> [MISP Instance B] <--sync--> [MISP Instance C]
       |                              |                            |
       v                              v                            v
  [Org A Events]              [Shared Events]               [Org C Events]
```

### Steps:
1. **Server Registration**: Register remote MISP instance with URL, API key, organization
2. **Sync Configuration**: Set sync direction (push/pull), filter rules, preview mode
3. **Pull Sync**: Pull events from remote instance matching filter criteria
4. **Push Sync**: Push local events to remote instance based on distribution level
5. **Conflict Resolution**: Handle attribute conflicts with priority rules
6. **Audit Logging**: Log all sync activities for compliance and troubleshooting

## Workflow 5: IOC Export for Defensive Tools

```
[MISP Events] --> [Export Module] --> [Format Conversion] --> [Defensive Tool]
                                             |
                                    +--------+--------+
                                    |        |        |
                                    v        v        v
                              [Suricata] [Bro/Zeek] [SIEM]
                               Rules     Intel      CSV/JSON
```

### Steps:
1. **Filter Selection**: Select events by tag, date range, threat level, to_ids flag
2. **Format Selection**: Choose output format (Suricata, Snort, Bro/Zeek, CSV, STIX, OpenIOC)
3. **Rule Generation**: Generate IDS/IPS rules from network IOCs
4. **SIEM Export**: Export to CSV/JSON for SIEM ingestion (Splunk, Elastic, QRadar)
5. **Automation**: Set up ZMQ/Kafka publishing for real-time IOC distribution
6. **Feedback Loop**: Track hit counts on exported IOCs, feed back to MISP for scoring
