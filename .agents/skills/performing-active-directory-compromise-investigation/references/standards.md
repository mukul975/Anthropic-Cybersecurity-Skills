# Standards and Frameworks for AD Compromise Investigation

## NIST SP 800-61 Rev 2 - Computer Security Incident Handling Guide
- Provides incident response lifecycle: Preparation, Detection & Analysis, Containment, Eradication & Recovery, Post-Incident Activity
- AD compromise investigations follow all four phases with emphasis on scoping the identity compromise

## CISA Alert: Detecting and Mitigating Active Directory Compromises
- Published guidance on AD-specific threats and detection methods
- Covers DCSync, Golden Ticket, Silver Ticket, and Kerberoasting attacks
- Recommends tiered administration, Protected Users group, and credential hygiene
- Reference: https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises

## MITRE ATT&CK Framework - Credential Access Tactics
- T1003.006: OS Credential Dumping - DCSync
- T1558.001: Steal or Forge Kerberos Tickets - Golden Ticket
- T1558.002: Steal or Forge Kerberos Tickets - Silver Ticket
- T1558.003: Steal or Forge Kerberos Tickets - Kerberoasting
- T1550.002: Use Alternate Authentication Material - Pass the Hash
- T1484.001: Domain Policy Modification - Group Policy Modification
- T1098: Account Manipulation

## Microsoft Security Best Practices
- Tiered administration model for Active Directory
- Privileged Access Workstations (PAWs) for domain admin tasks
- Microsoft Advanced Threat Analytics (ATA) / Defender for Identity
- LAPS (Local Administrator Password Solution) deployment
- Protected Users security group enforcement
- Reference: https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview

## CIS Benchmarks for Active Directory
- CIS Microsoft Windows Server Benchmark for DC hardening
- Password policy requirements (minimum 14 characters)
- Account lockout policy configuration
- Audit policy settings for security event logging
- GPO security baseline configurations

## SANS FOR500 - Windows Forensic Analysis
- Windows artifact analysis methodology
- Registry analysis for persistence detection
- Event log forensics for authentication tracking
- Timeline analysis techniques for AD compromise

## Semperis Identity Forensics and Incident Response (IFIR)
- AD-specific forensic methodology
- Replication metadata analysis
- Change tracking and rollback capabilities
- Forest recovery procedures
- Reference: https://www.semperis.com/solutions/active-directory-breach-forensics/

## Key Windows Security Event IDs for AD Monitoring
- Microsoft documentation on security auditing events
- Advanced Audit Policy Configuration for DCs
- Kerberos event logging requirements
- Directory Service Access auditing
