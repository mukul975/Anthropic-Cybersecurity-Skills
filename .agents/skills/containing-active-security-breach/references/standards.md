# Standards and Framework References

## NIST SP 800-61 Rev. 3 - Incident Response Recommendations
- **Respond (RS) Function**: Containment falls under RS.MI (Incident Mitigation)
  - RS.MI-01: Incidents are contained
  - RS.MI-02: Incidents are eradicated
- **Detect (DE) Function**: Scope identification maps to DE.AE (Adverse Event Analysis)
  - DE.AE-02: Potentially adverse events are analyzed to better understand associated activities
  - DE.AE-03: Information is correlated from multiple sources
- Reference: https://csrc.nist.gov/pubs/sp/800/61/r3/final

## NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide
- **Section 3.3**: Containment, Eradication, and Recovery
  - 3.3.1: Choosing a Containment Strategy
  - 3.3.2: Evidence Gathering and Handling
  - 3.3.3: Identifying the Attacking Hosts
- Containment strategy criteria: potential damage, evidence preservation needs, service availability, time/resources, effectiveness duration, solution scope
- Reference: https://csrc.nist.gov/pubs/sp/800/61/r2/final

## SANS PICERL Framework
- **Phase 3 - Containment**: The SANS Incident Handler's Handbook defines containment as actions to limit damage from an incident
  - Short-term containment: Immediate response to stop the bleeding
  - System back-up: Forensic image before remediation
  - Long-term containment: Temporary fixes allowing production use
- Reference: https://www.sans.org/white-papers/33901

## MITRE ATT&CK Framework - Relevant Techniques to Contain

### Initial Access (TA0001)
| Technique ID | Name | Containment Action |
|-------------|------|-------------------|
| T1566 | Phishing | Block sender, quarantine messages |
| T1190 | Exploit Public-Facing Application | Patch/WAF rule, isolate service |
| T1133 | External Remote Services | Disable VPN/RDP access |
| T1078 | Valid Accounts | Disable/reset compromised accounts |

### Lateral Movement (TA0008)
| Technique ID | Name | Containment Action |
|-------------|------|-------------------|
| T1021 | Remote Services | Block SMB/RDP/WinRM between segments |
| T1550 | Use Alternate Authentication Material | Reset tokens, rotate KRBTGT |
| T1570 | Lateral Tool Transfer | Block file sharing protocols |

### Command and Control (TA0011)
| Technique ID | Name | Containment Action |
|-------------|------|-------------------|
| T1071 | Application Layer Protocol | Block C2 domains/IPs at firewall |
| T1573 | Encrypted Channel | SSL inspection, block non-standard TLS |
| T1572 | Protocol Tunneling | Block DNS tunneling, inspect traffic |

### Exfiltration (TA0010)
| Technique ID | Name | Containment Action |
|-------------|------|-------------------|
| T1041 | Exfiltration Over C2 Channel | Sinkhole C2 domains |
| T1048 | Exfiltration Over Alternative Protocol | Block DNS/ICMP exfil |
| T1567 | Exfiltration Over Web Service | Block cloud storage uploads |

## CISA Incident Response Playbooks
- Federal Government Cybersecurity Incident and Vulnerability Response Playbooks
- Containment actions aligned with federal response guidelines
- Reference: https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf

## ISO/IEC 27035 - Information Security Incident Management
- Part 2: Guidelines to plan and prepare for incident response
- Containment classified as part of "Response" phase
- Emphasis on proportional response and business impact consideration
