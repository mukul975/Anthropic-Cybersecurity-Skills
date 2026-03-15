# Standards and Frameworks for Velociraptor IR Collection

## NIST SP 800-86 - Guide to Integrating Forensic Techniques
- Evidence collection procedures for digital investigations
- Chain of custody requirements for forensic data
- Volatile and non-volatile evidence prioritization

## ForensicArtifacts Standard
- YAML-based artifact definition format used by Velociraptor
- Cross-platform artifact repository
- Community-contributed artifact definitions
- Reference: https://github.com/ForensicArtifacts/artifacts

## SANS DFIR Collection Standards
- FOR500: Windows Forensic Analysis artifact prioritization
- FOR508: Advanced Incident Response collection methodology
- Evidence acquisition order of volatility
- Triage collection best practices

## Velociraptor Query Language (VQL) Reference
- SQL-like query language for endpoint interrogation
- Plugin system for extending collection capabilities
- Artifact definition YAML format
- Reference: https://docs.velociraptor.app/docs/vql/

## MITRE ATT&CK Framework
- Artifact mapping to ATT&CK techniques
- Detection-oriented collection strategies
- Threat-informed artifact selection
- Reference: https://attack.mitre.org/

## Sigma Detection Standard
- Velociraptor supports Sigma rule execution on endpoints
- Direct event log analysis without SIEM forwarding
- Community detection rules integration
- Reference: https://github.com/SigmaHQ/sigma

## CISA Recommended Practices
- Velociraptor listed as CISA-recommended tool
- Federal incident response procedures
- Evidence preservation requirements
- Reference: https://www.cisa.gov/resources-tools/services/velociraptor

## Rapid7 Integration Standards
- InsightIDR SIEM integration documentation
- Managed Detection and Response workflows
- Velociraptor alert forwarding specifications
