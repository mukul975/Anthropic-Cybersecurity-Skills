# Standards and Framework References - Incident Triage

## NIST SP 800-61 Rev. 3 - Incident Triage Alignment
- **Detect (DE)**: Alert analysis and triage
  - DE.AE-02: Potentially adverse events are analyzed to better understand associated activities
  - DE.AE-03: Information is correlated from multiple sources
  - DE.AE-04: The estimated impact and scope of adverse events is understood
- **Respond (RS)**: Incident classification and escalation
  - RS.AN-03: Analysis performed to establish awareness of incident scope
  - RS.CO-02: Incidents reported consistent with established criteria

## SANS PICERL - Identification Phase
- Phase 2 focuses on detecting and validating security events
- Triage determines if an event qualifies as an incident
- Key activities: alert validation, initial scoping, severity assignment
- Triage SLAs: P1 <15 min, P2 <30 min, P3 <1 hour, P4 <4 hours

## NIST Severity Classification (SP 800-61 Rev. 2, Table 3-2)
| Category | Definition | Examples |
|----------|-----------|----------|
| CAT 1 - Unauthorized Access | Individual gains access without permission | Compromised credentials, privilege escalation |
| CAT 2 - Denial of Service | Disruption of service availability | DDoS, resource exhaustion |
| CAT 3 - Malicious Code | Infection by malware | Virus, worm, trojan, ransomware |
| CAT 4 - Improper Usage | Violation of acceptable use policy | Unauthorized software, policy breach |
| CAT 5 - Scans/Probes | Reconnaissance activity | Port scans, vulnerability scans |
| CAT 6 - Investigation | Unconfirmed suspicious activity | Anomalous behavior under review |

## MITRE ATT&CK - Triage Technique Mapping
- Map observed techniques to ATT&CK framework during triage
- Technique identification helps select appropriate playbook
- Tactic identification reveals attacker's current phase
- Reference: https://attack.mitre.org/

## FIRST CSIRT Services Framework
- Triage falls under "Event Management" service area
- Key functions: Monitoring and Detection, Event Analysis, Incident Coordination
- Reference: https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1

## US-CERT Federal Incident Reporting Guidelines
- Category definitions for federal incident reporting
- Reporting timeframes based on incident category
- Reference: https://www.cisa.gov/federal-incident-notification-guidelines
