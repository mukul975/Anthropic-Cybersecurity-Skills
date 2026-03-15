# Standards & References - Deploying EDR Agent with CrowdStrike

## Primary Standards

### MITRE ATT&CK Enterprise Framework
- **Publisher**: MITRE Corporation
- **URL**: https://attack.mitre.org/
- **Relevance**: CrowdStrike Falcon maps detections to ATT&CK techniques; understanding ATT&CK is essential for tuning detection policies
- **Key tactics for EDR**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement

### NIST SP 800-83 Rev 1 - Guide to Malware Incident Prevention and Handling
- **Publisher**: NIST
- **Relevance**: Defines endpoint protection architecture including EDR placement and malware prevention controls

### CIS Control 10 - Malware Defenses
- **Publisher**: Center for Internet Security
- **Relevance**: CIS Controls v8 Control 10 mandates deploying anti-malware with centralized management and automated updates

## CrowdStrike-Specific References

### CrowdStrike Falcon Deployment Guide
- **Scope**: Official deployment procedures for Windows, macOS, Linux sensors
- **Key sections**: Silent install parameters, proxy configuration, sensor grouping tags
- **Access**: Falcon Console → Support → Documentation

### CrowdStrike Falcon API Documentation
- **URL**: https://falcon.crowdstrike.com/documentation/
- **Scope**: OAuth2 authentication, host management, detection management, RTR APIs
- **Key endpoints**: /devices/queries/devices/v1, /detects/queries/detects/v1

### Falcon SIEM Integration Guide
- **Scope**: Event streaming via SIEM Connector, FDR, and direct API
- **Supported SIEMs**: Splunk, Elastic, Microsoft Sentinel, IBM QRadar, ArcSight

## Compliance Mappings

| Framework | Requirement | CrowdStrike Coverage |
|-----------|------------|---------------------|
| PCI DSS 4.0 | 5.2 - Anti-malware on systems | Falcon sensor on all in-scope endpoints |
| HIPAA | 164.308(a)(5)(ii)(B) - Protection from malware | Falcon prevention + detection |
| SOC 2 | CC6.8 - Malicious software prevention | Falcon sensor with prevention policies |
| NIST 800-171 | 3.14.2 - Malicious code protection | Falcon ML + behavioral detection |
| ISO 27001 | A.12.2.1 - Controls against malware | Falcon sensor with automated response |

## Industry Benchmarks

- **MITRE Engenuity ATT&CK Evaluations**: CrowdStrike Falcon regularly achieves high detection scores in Enterprise evaluations
- **Gartner Magic Quadrant for Endpoint Protection**: CrowdStrike positioned as Leader
- **Forrester Wave Endpoint Detection and Response**: CrowdStrike rated Strong Performer/Leader
