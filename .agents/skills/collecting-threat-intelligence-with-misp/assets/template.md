# MISP Intelligence Collection Report Template

## Report Metadata
| Field | Value |
|-------|-------|
| Report ID | MISP-COL-YYYY-NNNN |
| Date Generated | YYYY-MM-DD HH:MM UTC |
| MISP Instance | https://misp.example.com |
| Collection Period | YYYY-MM-DD to YYYY-MM-DD |
| Classification | TLP:AMBER |
| Analyst | [Analyst Name] |

## Executive Summary

Brief overview of threat intelligence collected during the reporting period, including total events processed, notable threat campaigns identified, and key IOCs requiring immediate action.

## Collection Statistics

| Metric | Count |
|--------|-------|
| Total Events Processed | |
| New Events Created | |
| Attributes Collected | |
| IDS-Flagged Indicators | |
| Warninglist Filtered | |
| Feeds Active | |
| Correlations Found | |

## Feed Status

| Feed Name | Provider | Last Fetch | Status | Events Generated |
|-----------|----------|------------|--------|-----------------|
| CIRCL OSINT | CIRCL | | Active/Error | |
| Botvrij.eu | Botvrij | | Active/Error | |
| URLhaus | abuse.ch | | Active/Error | |
| PhishTank | OpenDNS | | Active/Error | |

## Top IOC Categories

### Network Indicators
| Type | Count | Sample Values |
|------|-------|---------------|
| IP Addresses (dst) | | |
| IP Addresses (src) | | |
| Domains | | |
| URLs | | |
| Hostnames | | |

### File Indicators
| Type | Count | Sample Values |
|------|-------|---------------|
| MD5 Hashes | | |
| SHA-1 Hashes | | |
| SHA-256 Hashes | | |
| Filenames | | |

### Email Indicators
| Type | Count | Sample Values |
|------|-------|---------------|
| Email Addresses | | |
| Email Subjects | | |
| Attachment Names | | |

## Notable Campaigns

### Campaign 1: [Campaign Name]
- **Threat Actor**: [Actor Name/Group]
- **MITRE ATT&CK Techniques**: T1566, T1059, T1071
- **IOC Count**: N indicators
- **First Seen**: YYYY-MM-DD
- **TLP**: AMBER
- **Key Indicators**:
  - IP: x.x.x.x (C2 Server)
  - Domain: malicious-domain.com
  - SHA256: [hash]

## Correlation Highlights

Events sharing common indicators across multiple campaigns or threat actors:

| Indicator | Events Linked | Threat Actors | Confidence |
|-----------|--------------|---------------|------------|
| | | | High/Medium/Low |

## Export Summary

| Format | Destination | Record Count | Timestamp |
|--------|-------------|-------------|-----------|
| STIX 2.1 | OpenCTI | | |
| Suricata Rules | IDS/IPS | | |
| CSV | SIEM (Splunk) | | |
| JSON | Threat Hunting | | |

## Recommendations

1. **Immediate Actions**: Block high-confidence IOCs in firewall/proxy
2. **Monitoring**: Add medium-confidence IOCs to watchlists
3. **Investigation**: Review events tagged with threat level "high"
4. **Feed Maintenance**: Review and update feed configurations
5. **Sharing**: Publish sanitized events to community instances

## Appendix: IOC Export

Full IOC list exported to:
- `misp_iocs_export.csv` - CSV format for SIEM ingestion
- `misp_stix_bundle.json` - STIX 2.1 bundle for CTI platforms
- `misp_suricata.rules` - Suricata IDS rules for network detection
