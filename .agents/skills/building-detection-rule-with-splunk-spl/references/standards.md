# Standards and References - Splunk SPL Detection Rules

## Industry Standards

### MITRE ATT&CK Framework
- Primary mapping standard for detection rule categorization
- Version 18.1 (December 2025) is the latest release
- Use ATT&CK Navigator for visual coverage mapping

### Splunk Common Information Model (CIM)
- Standard field naming convention for normalized data
- Data models: Authentication, Network_Traffic, Endpoint, Web, Email
- Enables cross-sourcetype correlation searches

### NIST SP 800-92 - Guide to Computer Security Log Management
- Log management planning and policy guidance
- Defines log collection, analysis, and retention best practices

### NIST SP 800-61 Rev 2 - Computer Security Incident Handling Guide
- Incident detection and analysis procedures
- Defines severity classification for generated alerts

## Splunk Enterprise Security Resources

### Correlation Search Framework
- Supports scheduled searches with adaptive response actions
- Risk-based alerting (RBA) aggregates risk events by entity
- Notable events are the primary output for SOC analyst review

### Data Model Acceleration
- tstats provides fast summary-based searching
- Accelerated data models required for production correlation searches
- CIM compliance ensures cross-source detection capability

### Key Splunk SPL Commands for Detection

| Command | Purpose |
|---|---|
| `stats` | Aggregate events by fields |
| `tstats` | Fast search over accelerated data models |
| `eventstats` | Add aggregated stats inline to events |
| `streamstats` | Running statistics over ordered events |
| `transaction` | Group related events into transactions |
| `lookup` | Enrich events with external data |
| `where` | Filter results with boolean expressions |
| `eval` | Create calculated fields |

## Detection Engineering Maturity Model

### Level 1 - Basic Threshold Rules
- Simple count-based thresholds
- Single data source correlation

### Level 2 - Multi-Source Correlation
- Cross-source event correlation
- Asset and identity enrichment

### Level 3 - Behavioral Analytics
- Baseline deviation detection
- User and entity behavior profiling

### Level 4 - Risk-Based Alerting
- Cumulative risk scoring per entity
- Context-aware severity assignment

### Level 5 - Automated Response
- Adaptive response action integration
- SOAR playbook triggering from notable events
