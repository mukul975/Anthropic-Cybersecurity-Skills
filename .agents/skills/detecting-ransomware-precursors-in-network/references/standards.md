# Standards & References - Detecting Ransomware Precursors

## MITRE ATT&CK Mapping

### Initial Access (TA0001)
- T1078: Valid Accounts (compromised credentials from IABs)
- T1133: External Remote Services (VPN/RDP exploitation)
- T1566: Phishing (email-based initial access)

### Command and Control (TA0011)
- T1071.001: Application Layer Protocol: Web (HTTPS beacons)
- T1071.004: Application Layer Protocol: DNS (DNS tunneling)
- T1573: Encrypted Channel (C2 over TLS)
- T1090: Proxy (redirectors and relay infrastructure)

### Credential Access (TA0006)
- T1558.003: Kerberoasting
- T1003.006: DCSync
- T1557: Adversary-in-the-Middle (NTLM relay)

### Discovery (TA0007)
- T1046: Network Service Discovery (port scanning)
- T1018: Remote System Discovery (AD enumeration)
- T1087: Account Discovery

### Lateral Movement (TA0008)
- T1021.002: Remote Services: SMB/Windows Admin Shares
- T1021.001: Remote Services: RDP
- T1047: Windows Management Instrumentation (WMI)
- T1569.002: System Services: Service Execution (PsExec)

## Industry References

### CISA Advisories
- AA23-136A: #StopRansomware - BianLian Ransomware Group
- AA23-158A: #StopRansomware - CL0P Ransomware Gang
- AA24-131A: #StopRansomware - Black Basta
- AA23-165A: Understanding Ransomware Threat Actors: LockBit

### NIST
- SP 800-94 Rev 1: Guide to Intrusion Detection and Prevention Systems
- SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- IR 8374: Ransomware Risk Management

### Threat Intelligence Sources
- abuse.ch Feodo Tracker: https://feodotracker.abuse.ch/
- abuse.ch ThreatFox: https://threatfox.abuse.ch/
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Emerging Threats Ruleset: https://rules.emergingthreats.net/
