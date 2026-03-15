# Standards and References - Scanning Infrastructure with Nessus

## Industry Standards
- **NIST SP 800-115**: Technical Guide to Information Security Testing and Assessment
- **NIST SP 800-53 RA-5**: Vulnerability Monitoring and Scanning control family
- **PCI DSS v4.0 Requirement 11.3**: Internal and external vulnerability scanning
- **CIS Controls v8 Control 7**: Continuous Vulnerability Management
- **ISO 27001:2022 A.8.8**: Management of technical vulnerabilities

## Tenable Documentation
- Tenable Nessus User Guide: https://docs.tenable.com/nessus/
- Nessus REST API Reference: https://docs.tenable.com/nessus/api/
- Nessus Command Line Reference (January 2026): https://docs.tenable.com/nessus/command-line-reference/
- Nessus Plugin Families: https://www.tenable.com/plugins/nessus/families
- Tenable Agent CLI Commands: https://docs.tenable.com/agent/Content/NessusCLIAgent.htm

## CVE and Vulnerability Databases
- National Vulnerability Database (NVD): https://nvd.nist.gov/
- MITRE CVE Program: https://cve.mitre.org/
- Tenable Plugin Database: https://www.tenable.com/plugins
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Compliance Audit Files
- CIS Benchmarks: https://www.cisecurity.org/benchmark
- DISA STIGs: https://public.cyber.mil/stigs/
- PCI DSS ASV Scanning: https://www.pcisecuritystandards.org/assessors_and_solutions/approved_scanning_vendors

## Scan Configuration Standards
| Parameter | Recommended Value | Notes |
|-----------|------------------|-------|
| Port Range | 1-65535 (full) | For comprehensive scanning |
| Scan Speed | Normal | Balance between speed and accuracy |
| Max Concurrent Hosts | 30 | Adjust based on network capacity |
| Max Concurrent Checks per Host | 5 | Prevent host overload |
| Network Timeout | 5 seconds | Increase for high-latency networks |
| Plugin Timeout | 320 seconds | Default; increase for slow targets |
