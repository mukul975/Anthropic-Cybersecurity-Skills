# Standards and References - AD CS ESC1 Exploitation

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|-------------|------|--------|
| T1649 | Steal or Forge Authentication Certificates | Credential Access |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Credential Access |
| T1078.002 | Valid Accounts: Domain Accounts | Initial Access, Persistence |
| T1484 | Domain Policy Modification | Defense Evasion |
| T1087.002 | Account Discovery: Domain Account | Discovery |

## Key Research

- SpecterOps "Certified Pre-Owned" whitepaper by Will Schroeder and Lee Christensen (2021)
- CrowdStrike: Investigating Active Directory Certificate Services Abuse: ESC1
- BeyondTrust: ESC1 Attack - How to Detect and Mitigate
- Semperis: ESC1 Attack Explained
- HackTricks: AD CS Domain Escalation

## CVE References

- ESC1 is a misconfiguration, not a specific CVE
- Related: CVE-2022-26923 (Certifried) - AD CS machine account certificate abuse

## Remediation Standards

- Microsoft KB5014754: Certificate-based authentication changes
- CISA Alert: Securing AD CS deployments
- CIS Benchmark: AD CS hardening guidelines
