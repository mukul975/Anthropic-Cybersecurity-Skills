# Standards — Active Directory Penetration Testing

## Key Frameworks
- MITRE ATT&CK for Enterprise: https://attack.mitre.org/matrices/enterprise/
- ANSSI AD Security Guide: https://www.cert.ssi.gouv.fr/uploads/guide-ad.html
- Microsoft Tiered Administration Model: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model

## MITRE ATT&CK Techniques for AD Testing

| Technique | ID | Description |
|-----------|----|-------------|
| Kerberoasting | T1558.003 | Steal Kerberos TGS tickets for offline cracking |
| AS-REP Roasting | T1558.004 | Target accounts without pre-auth |
| DCSync | T1003.006 | Replicate domain credentials via DRSUAPI |
| Golden Ticket | T1558.001 | Forge TGT using krbtgt hash |
| Pass-the-Hash | T1550.002 | Authenticate using NTLM hash |
| Unconstrained Delegation | T1558 | Abuse delegation to steal TGTs |
| ADCS Abuse | T1649 | Exploit misconfigured certificate templates |

## AD Security Benchmarks
- CIS Microsoft Windows Server Benchmark
- STIG (Security Technical Implementation Guide) for Windows
- Microsoft Security Compliance Toolkit
