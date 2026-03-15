# Standards and Framework References - Malware Eradication

## NIST SP 800-61 Rev. 3 - Eradication Alignment
- **Respond (RS.MI-02)**: Incidents are eradicated
- Eradication follows containment; remove all attacker artifacts
- Must address root cause, not just symptoms
- Verify eradication before moving to recovery

## NIST SP 800-83 - Guide to Malware Incident Prevention and Handling
- Section 4: Handling Malware Incidents
  - 4.3: Containment and Eradication
  - 4.3.1: Identification of infected hosts
  - 4.3.2: Containment options (quarantine, disconnect, block)
  - 4.3.3: Eradication and recovery options
- Reference: https://csrc.nist.gov/pubs/sp/800/83/r1/final

## SANS PICERL - Eradication Phase
- Phase 4 of SANS incident handling process
- Remove malware and attacker tools from all affected systems
- Identify and remediate the root cause
- Improve defenses based on attack methods used

## MITRE ATT&CK - Persistence Techniques to Eradicate

### Windows Persistence (T1547)
| Sub-technique | Location | Eradication Method |
|--------------|----------|-------------------|
| T1547.001 | Registry Run Keys | Delete malicious registry values |
| T1547.004 | Winlogon Helper DLL | Restore legitimate DLL path |
| T1547.005 | Security Support Provider | Remove from registry |
| T1547.009 | Shortcut Modification | Restore original shortcuts |

### Scheduled Task/Job (T1053)
| Sub-technique | Location | Eradication Method |
|--------------|----------|-------------------|
| T1053.005 | Scheduled Task | schtasks /delete |
| T1053.003 | Cron | Remove crontab entries |
| T1053.006 | Systemd Timers | Disable and remove timer units |

### Create/Modify System Process (T1543)
| Sub-technique | Location | Eradication Method |
|--------------|----------|-------------------|
| T1543.003 | Windows Service | sc delete ServiceName |
| T1543.002 | Systemd Service | systemctl disable + rm unit file |
| T1543.001 | Launch Agent | Remove plist file |

### Other Persistence
| Technique | Description | Eradication |
|-----------|-------------|-------------|
| T1546.003 | WMI Event Subscription | Remove filter, consumer, binding |
| T1546.015 | COM Object Hijacking | Restore CLSID registry values |
| T1098 | Account Manipulation | Remove backdoor accounts |
| T1136 | Create Account | Delete unauthorized accounts |
| T1556 | Modify Authentication | Restore authentication mechanisms |
| T1505.003 | Web Shell | Remove web shell files |

## CISA Malware Analysis Reports (MARs)
- Published IOCs and eradication guidance for specific threats
- Reference: https://www.cisa.gov/news-events/cybersecurity-advisories

## Microsoft DART Eradication Guidance
- Recommended approach for Active Directory compromise recovery
- KRBTGT password reset procedures
- Tiered administration model implementation
- Reference: Microsoft Incident Response playbooks
