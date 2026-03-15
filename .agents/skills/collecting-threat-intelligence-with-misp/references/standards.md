# Standards and Frameworks Reference

## MISP Standards

### MISP Core Format
- **MISP JSON Format**: Native event format used for synchronization between instances
- **MISP Galaxy**: Cluster-based knowledge base linked to MITRE ATT&CK, threat actors, tools
- **MISP Taxonomies**: Machine-readable tagging schemes (TLP, PAP, admiralty-scale, OSINT)
- **MISP Warninglists**: Lists of well-known indicators to reduce false positives (Alexa Top 1M, Office 365 IPs)

### STIX 2.1 (Structured Threat Information Expression)
- Standard language for representing cyber threat intelligence
- MISP supports import/export of STIX 2.1 bundles
- Object types: Indicator, Malware, Threat Actor, Attack Pattern, Campaign, Observed Data
- Relationship types: uses, targets, attributed-to, indicates, mitigates

### TAXII 2.1 (Trusted Automated Exchange of Intelligence Information)
- Transport protocol for sharing CTI over HTTPS
- MISP can consume TAXII feeds and serve as a TAXII server
- Collection-based model: discovery, API root, collections, objects
- Supports pagination and filtering by added_after, type, version

## MITRE ATT&CK Integration
- MISP Galaxy clusters map directly to ATT&CK techniques (T-codes)
- Events can be tagged with ATT&CK tactics: Initial Access, Execution, Persistence, etc.
- ATT&CK Navigator integration for visualizing technique coverage
- Sub-technique support (e.g., T1566.001 - Spearphishing Attachment)

## Traffic Light Protocol (TLP)
- **TLP:CLEAR** (formerly TLP:WHITE): Unlimited disclosure
- **TLP:GREEN**: Limited disclosure within community
- **TLP:AMBER**: Limited disclosure within organization
- **TLP:AMBER+STRICT**: Restricted to organization only
- **TLP:RED**: Restricted to specific recipients only

## Permissible Actions Protocol (PAP)
- **PAP:RED**: Only passive actions (no external lookups)
- **PAP:AMBER**: Active actions allowed but not against infrastructure
- **PAP:GREEN**: Active actions allowed
- **PAP:CLEAR**: Unlimited use

## References
- [MISP Standard Format RFC](https://www.misp-standard.org/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [TLP Standard](https://www.first.org/tlp/)
