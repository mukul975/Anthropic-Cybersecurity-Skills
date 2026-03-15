# Standards and Frameworks Reference

## STIX 2.1 (Native Data Model for OpenCTI)

### STIX Domain Objects (SDOs)
- **Indicator**: Contains detection patterns (STIX patterning, YARA, Sigma)
- **Malware**: Represents malware families and variants
- **Threat Actor**: Describes adversary groups and individuals
- **Campaign**: Groups related intrusion activity
- **Attack Pattern**: Maps to MITRE ATT&CK techniques
- **Infrastructure**: Represents adversary-owned systems (C2, exploit kits)
- **Tool**: Legitimate software used by adversaries

### STIX Cyber Observables (SCOs)
- **IPv4-Addr / IPv6-Addr**: Network addresses
- **Domain-Name**: DNS domain names
- **URL**: Full URL indicators
- **StixFile**: File hashes (MD5, SHA-1, SHA-256)
- **Email-Addr**: Email addresses
- **Artifact**: Binary content (malware samples)
- **Process**: Running process information
- **Network-Traffic**: Network flow data

### STIX Relationship Objects (SROs)
- **Relationship**: Connects two SDOs (e.g., Threat Actor "uses" Malware)
- **Sighting**: Records observation of an indicator or malware

## OpenCTI Connector Standards

### Connector Types
1. **EXTERNAL_IMPORT**: Ingest data from external sources (MISP, TAXII feeds)
2. **INTERNAL_IMPORT_FILE**: Parse uploaded files (PDF reports, STIX bundles)
3. **INTERNAL_ENRICHMENT**: Enrich existing observables with external data
4. **INTERNAL_ANALYSIS**: Analyze content for indicators
5. **STREAM**: Real-time export to external systems (SIEM, SOAR)

### Connector Communication Protocol
- Connectors communicate via RabbitMQ message queues
- Messages contain STIX 2.1 bundles in JSON format
- Enrichment connectors receive entity_id and return STIX bundles
- Rate limiting and retry logic handled by connector framework

## Enrichment Service APIs

### VirusTotal v3 API
- Endpoint: `https://www.virustotal.com/api/v3/`
- Resources: files, urls, domains, ip_addresses
- Rate limits: 4 requests/minute (free), 1000/minute (premium)
- Returns: detection ratios, behavioral analysis, relationships

### Shodan API
- Endpoint: `https://api.shodan.io/`
- Resources: host/{ip}, dns/resolve, search
- Returns: open ports, services, banners, vulnerabilities, ASN info

### AbuseIPDB v2 API
- Endpoint: `https://api.abuseipdb.com/api/v2/`
- Resources: check, reports, blacklist
- Returns: abuse confidence score, total reports, categories, country

### GreyNoise v3 API
- Endpoint: `https://api.greynoise.io/v3/`
- Resources: community/{ip}, noise/context/{ip}
- Returns: classification (benign/malicious/unknown), RIOT status, tags

## MITRE ATT&CK Framework
- OpenCTI maps Attack Patterns to ATT&CK techniques
- Supports Enterprise, Mobile, and ICS matrices
- Technique relationships enable campaign-level analysis
- Sub-technique granularity (e.g., T1059.001 - PowerShell)

## References
- [OpenCTI Documentation](https://docs.opencti.io/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [OpenCTI GitHub](https://github.com/OpenCTI-Platform/opencti)
- [OpenCTI Connectors Ecosystem](https://docs.opencti.io/latest/deployment/connectors/)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
