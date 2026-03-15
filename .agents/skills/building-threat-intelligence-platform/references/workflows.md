# TIP Architecture Workflows

## Workflow 1: End-to-End Intelligence Pipeline
```
[External Feeds] --> [MISP] --> [OpenCTI] --> [Enrichment (Cortex)] --> [SIEM/TheHive]
    |                   |            |                |                       |
    v                   v            v                v                       v
OSINT/Commercial   Correlate    Knowledge Graph   VT/Shodan/AIPDB    Alerts/Cases
```

## Workflow 2: Incident-to-Intelligence Feedback Loop
```
[SOC Alert] --> [TheHive Case] --> [Cortex Analysis] --> [IOC Extraction]
                                                               |
                                                               v
                                                    [MISP Event Creation]
                                                               |
                                                               v
                                                    [OpenCTI Knowledge Update]
                                                               |
                                                               v
                                                    [Updated Detections --> SIEM]
```

## Workflow 3: Platform Health Monitoring
```
[Prometheus/Grafana] --> [Component Health] --> [Feed Status] --> [Alert on Failure]
                              |                      |
                              v                      v
                     [ES Cluster Health]    [Connector Status]
```
