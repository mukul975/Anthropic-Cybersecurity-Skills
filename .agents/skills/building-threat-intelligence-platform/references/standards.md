# Standards and Frameworks Reference

## TIP Architecture Standards
- **STIX 2.1**: Native data model for CTI representation
- **TAXII 2.1**: Transport protocol for CTI sharing
- **MITRE ATT&CK**: Technique taxonomy for TTP mapping
- **Diamond Model**: Intrusion analysis framework
- **Kill Chain**: Lockheed Martin Cyber Kill Chain for attack phase tracking

## Platform Component Standards
| Component | Protocol | Data Format |
|-----------|----------|-------------|
| MISP | REST API | MISP JSON, STIX 2.1 |
| OpenCTI | GraphQL API | STIX 2.1 |
| TheHive | REST API | TheHive JSON |
| Cortex | REST API | Cortex Report JSON |
| Elasticsearch | REST API | JSON |

## Integration Standards
- **MISP Sync Protocol**: Push/Pull over HTTPS with API key auth
- **OpenCTI Connectors**: RabbitMQ-based message queue for async processing
- **Cortex Analyzers**: Docker-based analyzers with standardized I/O
- **SIEM Integration**: Syslog, Kafka, REST API, or file-based export

## References
- [OpenCTI Architecture](https://docs.opencti.io/latest/deployment/overview/)
- [MISP Architecture](https://www.misp-project.org/features/)
- [TheHive Documentation](https://docs.strangebee.com/)
