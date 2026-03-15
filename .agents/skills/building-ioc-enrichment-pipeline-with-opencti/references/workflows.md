# OpenCTI IOC Enrichment Workflows

## Workflow 1: Automatic Enrichment Pipeline

```
[New Observable Created] --> [RabbitMQ Queue] --> [Enrichment Connectors]
                                                        |
                                            +-----------+-----------+
                                            |           |           |
                                            v           v           v
                                      [VirusTotal] [Shodan]  [AbuseIPDB]
                                            |           |           |
                                            v           v           v
                                     [STIX Bundle] [STIX Bundle] [STIX Bundle]
                                            |           |           |
                                            +-----------+-----------+
                                                        |
                                                        v
                                              [Merged into OpenCTI]
                                                        |
                                                        v
                                              [Confidence Updated]
```

### Steps:
1. **Observable Ingestion**: New IP/domain/hash created via feed import or manual entry
2. **Queue Distribution**: OpenCTI sends observable to enrichment connector queues
3. **Parallel Enrichment**: Each connector queries its respective external API
4. **STIX Bundle Generation**: Connectors produce STIX 2.1 bundles with notes, labels, relationships
5. **Merge**: Enrichment results merged into the observable's knowledge graph
6. **Scoring**: Confidence score updated based on aggregated enrichment data

## Workflow 2: Analyst-Triggered Enrichment

```
[Analyst Selects Observable] --> [Manual Enrichment Request] --> [Selected Connectors]
         |                                                              |
         v                                                              v
  [Review Results] <-- [Enrichment Dashboard] <-- [Results Returned]
         |
         v
  [Update Tags/Labels] --> [Add to Investigation]
```

### Steps:
1. **Selection**: Analyst identifies observable requiring additional context
2. **Connector Choice**: Select specific enrichment connectors to run
3. **Execution**: Connectors query external services with observable value
4. **Review**: Analyst reviews enrichment results in observable detail view
5. **Curation**: Analyst updates labels, confidence, and adds notes
6. **Investigation**: Link enriched observable to ongoing investigation case

## Workflow 3: Bulk Enrichment Pipeline

```
[STIX Import] --> [Observable Extraction] --> [Batch Queue] --> [Rate-Limited Enrichment]
                                                                         |
                                                                         v
                                                              [Progress Tracking]
                                                                         |
                                                                         v
                                                              [Enrichment Report]
```

### Steps:
1. **Bulk Import**: Import STIX bundle with hundreds of observables
2. **Extraction**: OpenCTI extracts unique observables from imported data
3. **Queue Management**: Observables queued for enrichment with rate limiting
4. **Progressive Enrichment**: Connectors process queue respecting API rate limits
5. **Monitoring**: Track enrichment progress via connector status dashboard
6. **Reporting**: Generate enrichment summary with coverage statistics

## Workflow 4: Enrichment-Driven Scoring

```
[Raw IOC (Score: 0)] --> [VirusTotal] --> [Score += VT_detections/total * 30]
                              |
                              v
                         [AbuseIPDB] --> [Score += abuse_confidence * 0.3]
                              |
                              v
                         [GreyNoise] --> [Score += classification_weight]
                              |
                              v
                         [Shodan] --> [Score += open_ports_risk]
                              |
                              v
                    [Final Score (0-100)] --> [Priority Classification]
                              |
                    +---------+---------+
                    |         |         |
                    v         v         v
              [Critical]  [High]    [Low]
              (80-100)   (50-79)   (0-49)
```

### Steps:
1. **Baseline**: Observable starts with confidence score of 0
2. **VT Score**: VirusTotal detection ratio contributes up to 30 points
3. **Abuse Score**: AbuseIPDB confidence contributes up to 30 points
4. **Classification**: GreyNoise malicious/benign classification adds/subtracts points
5. **Exposure**: Shodan data on open ports and known vulnerabilities adds risk points
6. **Final Priority**: Aggregated score determines analyst priority queue placement
