# Standards and Framework References - Ransomware Incident Response

## NIST SP 800-61 Rev. 3 - Ransomware Response Alignment
- **Detect (DE)**: Monitoring for ransomware indicators
  - DE.CM-01: Networks monitored for ransomware C2 traffic
  - DE.AE-02: Anomalous file encryption patterns analyzed
- **Respond (RS)**: Containment and eradication
  - RS.AN-03: Analysis performed to determine ransomware variant
  - RS.MI-01: Contain ransomware spread via network isolation
  - RS.MI-02: Eradicate ransomware persistence mechanisms
- **Recover (RC)**: Restoration from backups
  - RC.RP-01: Recovery plan executed during or after incident
  - RC.CO-03: Recovery activities communicated to stakeholders

## CISA Ransomware Guide (StopRansomware.gov)
- Joint advisory from CISA, FBI, NSA, MS-ISAC
- Key recommendations:
  1. Maintain offline, encrypted backups
  2. Create, maintain, and exercise a basic cyber incident response plan
  3. Implement Zero Trust Architecture
  4. Segment networks to prevent spread
- Reference: https://www.cisa.gov/stopransomware

## NIST Cybersecurity Framework Profile for Ransomware Risk Management
- NISTIR 8374: Provides a Ransomware Profile mapped to CSF
- Key subcategories:
  - PR.DS-01: Data-at-rest is protected (backup encryption)
  - PR.IP-04: Backups of information are conducted, maintained, and tested
  - DE.AE-05: Incident alert thresholds are established
- Reference: https://csrc.nist.gov/publications/detail/nistir/8374/final

## MITRE ATT&CK - Ransomware Techniques

### Pre-Encryption Techniques
| Technique ID | Name | Description |
|-------------|------|-------------|
| T1486 | Data Encrypted for Impact | Core ransomware encryption activity |
| T1490 | Inhibit System Recovery | Deleting shadow copies, disabling recovery |
| T1489 | Service Stop | Stopping AV, backup, database services |
| T1562.001 | Disable or Modify Tools | Disabling security tools before encryption |
| T1047 | Windows Management Instrumentation | WMI used for lateral deployment |

### Ransomware Deployment Techniques
| Technique ID | Name | Description |
|-------------|------|-------------|
| T1570 | Lateral Tool Transfer | Copying ransomware binary across network |
| T1053.005 | Scheduled Task | Scheduled tasks for timed detonation |
| T1484.001 | Group Policy Modification | GPO abuse for mass deployment |
| T1569.002 | Service Execution | Running ransomware as a service |

### Exfiltration (Double Extortion)
| Technique ID | Name | Description |
|-------------|------|-------------|
| T1567 | Exfiltration Over Web Service | Uploading data to cloud storage |
| T1048 | Exfiltration Over Alternative Protocol | DNS/ICMP tunneling for data theft |
| T1041 | Exfiltration Over C2 Channel | Data sent through C2 infrastructure |

## SANS Ransomware Response Checklist
1. Isolate the infected device(s) from the network immediately
2. Identify the ransomware variant
3. Check for decryptors (No More Ransom, Emsisoft, Kaspersky)
4. Report to law enforcement (FBI IC3, local CISA office)
5. Assess backup availability and integrity
6. Determine if data was exfiltrated (double extortion)
7. Restore from clean backups
8. Document lessons learned

## FBI/CISA Joint Advisory Recommendations
- Do NOT pay the ransom (paying does not guarantee recovery)
- Report the attack to FBI IC3 (ic3.gov) and CISA
- Preserve forensic evidence for law enforcement
- Contact CISA for technical assistance
- Share IOCs with sector ISACs

## Known Ransomware Family References
| Family | First Seen | Notable Traits | Decryptor Available |
|--------|-----------|----------------|-------------------|
| LockBit 3.0 | 2022 | RaaS, Bug Bounty program | No |
| BlackCat/ALPHV | 2021 | Rust-based, cross-platform | Partial (FBI tool) |
| Cl0p | 2019 | Mass exploitation campaigns | No |
| Royal/BlackSuit | 2022 | Targets critical infrastructure | No |
| Play | 2022 | Intermittent encryption | No |
| Akira | 2023 | Targets Linux/VMware | Partial |
| Rhysida | 2023 | Targets healthcare, education | No |
