# Standards - Threat Intelligence Enrichment in Splunk

## Threat Intelligence Standards

### STIX (Structured Threat Information eXpression)
- Version 2.1 is the current standard for representing threat intelligence
- Defines objects: Indicator, Malware, Attack Pattern, Threat Actor, Campaign
- Used as the interchange format between TI platforms and SIEMs

### TAXII (Trusted Automated eXchange of Indicator Information)
- Transport mechanism for STIX data
- TAXII 2.1 provides RESTful API for feed collection
- Supports Collection and Channel sharing models

### OpenIOC
- Mandiant's open framework for sharing IOCs
- XML-based format for indicator definitions

### OCSF (Open Cybersecurity Schema Framework)
- Industry standard for normalizing security event data
- Version 1.0 released at BlackHat 2023

## Splunk CIM Data Models for TI

| Data Model | TI Correlation Fields |
|---|---|
| Network_Traffic | src_ip, dest_ip, dest_port |
| Web | url, http_user_agent, domain |
| Email | src_user, file_hash, url |
| Endpoint | process_hash, file_hash, dest |
| Authentication | src_ip, user, app |
| DNS | query, answer, src_ip |

## IOC Types and Confidence Levels

| IOC Type | Splunk Field | Confidence Threshold |
|---|---|---|
| IP Address | ip_intel | > 70% |
| Domain | domain_intel | > 70% |
| File Hash (SHA256) | file_intel | > 80% |
| URL | url_intel | > 75% |
| Email Address | email_intel | > 80% |
