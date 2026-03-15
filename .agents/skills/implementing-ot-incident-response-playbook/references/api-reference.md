# API Reference: Implementing OT Incident Response Playbook

## ICS-CERT Incident Categories

| Category | Severity | Description | Response Time |
|----------|----------|-------------|---------------|
| Unauthorized Access | P1 - Critical | PLC/HMI/SIS unauthorized access | Immediate |
| Malware/Ransomware | P1 - Critical | OT network malware (EKANS, Triton) | Immediate |
| DoS/DDoS | P1 - Critical | OT communication disruption | Immediate |
| Network Intrusion | P2 - High | IT-OT boundary breach | < 4 hours |
| Reconnaissance | P3 - Medium | OT network scanning detected | < 24 hours |
| Policy Violation | P4 - Low | Unauthorized configuration change | < 72 hours |

## Purdue Model Containment Zones

| Level | Name | Containment Action |
|-------|------|--------------------|
| L0 | Physical Process | Manual control, verify SIS |
| L1 | Basic Control (PLC, SIS) | Isolate network, do NOT power off |
| L2 | Supervisory (HMI, SCADA) | Disconnect HMI, activate backup |
| L3 | Operations (Historian) | Isolate segment, preserve logs |
| L3.5 | DMZ | Sever IT-OT bridge |
| L4-5 | Enterprise IT | Standard IT IR procedures |

## NIST SP 800-82 IR Controls

| Control | Title | OT Consideration |
|---------|-------|------------------|
| IR-1 | IR Policy | Must address safety-critical systems |
| IR-4 | Incident Handling | Include OT engineering team |
| IR-5 | Incident Monitoring | Passive monitoring only in OT |
| IR-6 | Incident Reporting | CISA ICS-CERT within 72 hours |
| IR-8 | IR Plan | Separate OT and IT playbooks |

## SANS PICERL Framework for OT

| Phase | OT-Specific Actions |
|-------|---------------------|
| Preparation | Maintain PLC backup programs, define safe states |
| Identification | Correlate OT alerts with process anomalies |
| Containment | Network isolation without process disruption |
| Eradication | Restore from known-good PLC/HMI configurations |
| Recovery | Staged restart with operator verification |
| Lessons Learned | Update OT-specific TTPs and detection rules |

## Reporting Obligations

| Authority | Timeframe | Trigger |
|-----------|-----------|---------|
| CISA ICS-CERT | 72 hours | Critical infrastructure impact |
| Sector ISAC | 48 hours | Sector-relevant threat |
| TSA (pipeline) | 12 hours | Pipeline cybersecurity incident |
| NERC (electric) | 1 hour | Cyber Security Incident |

### References

- NIST SP 800-82 Rev 3: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
- IEC 62443-4-2: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- CISA ICS-CERT: https://www.cisa.gov/topics/industrial-control-systems
