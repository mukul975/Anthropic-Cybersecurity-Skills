# Standards and References: Full-Scope Red Team Engagement

## MITRE ATT&CK Techniques

### Reconnaissance (TA0043)
- **T1593** - Search Open Websites/Domains
- **T1593.001** - Social Media
- **T1593.002** - Search Engines
- **T1589** - Gather Victim Identity Information
- **T1589.001** - Credentials
- **T1589.002** - Email Addresses
- **T1590** - Gather Victim Network Information
- **T1590.002** - DNS
- **T1590.005** - IP Addresses
- **T1591** - Gather Victim Org Information

### Resource Development (TA0042)
- **T1583.001** - Acquire Infrastructure: Domains
- **T1583.003** - Acquire Infrastructure: Virtual Private Server
- **T1587.001** - Develop Capabilities: Malware
- **T1587.003** - Develop Capabilities: Digital Certificates
- **T1608.001** - Stage Capabilities: Upload Malware

### Initial Access (TA0001)
- **T1566.001** - Phishing: Spearphishing Attachment
- **T1566.002** - Phishing: Spearphishing Link
- **T1190** - Exploit Public-Facing Application
- **T1078** - Valid Accounts
- **T1133** - External Remote Services
- **T1195.002** - Supply Chain Compromise: Compromise Software Supply Chain

### Execution (TA0002)
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1059.003** - Command and Scripting Interpreter: Windows Command Shell
- **T1204.001** - User Execution: Malicious Link
- **T1204.002** - User Execution: Malicious File
- **T1047** - Windows Management Instrumentation

### Persistence (TA0003)
- **T1053.005** - Scheduled Task/Job: Scheduled Task
- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys
- **T1136.001** - Create Account: Local Account
- **T1098** - Account Manipulation

### Privilege Escalation (TA0004)
- **T1068** - Exploitation for Privilege Escalation
- **T1548.002** - Abuse Elevation Control Mechanism: Bypass User Account Control
- **T1134** - Access Token Manipulation

### Defense Evasion (TA0005)
- **T1055** - Process Injection
- **T1027** - Obfuscated Files or Information
- **T1562.001** - Impair Defenses: Disable or Modify Tools
- **T1070.004** - Indicator Removal: File Deletion

### Credential Access (TA0006)
- **T1003.001** - OS Credential Dumping: LSASS Memory
- **T1003.006** - OS Credential Dumping: DCSync
- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting
- **T1110** - Brute Force

### Discovery (TA0007)
- **T1087.002** - Account Discovery: Domain Account
- **T1018** - Remote System Discovery
- **T1069.002** - Permission Groups Discovery: Domain Groups
- **T1082** - System Information Discovery

### Lateral Movement (TA0008)
- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1021.001** - Remote Services: Remote Desktop Protocol
- **T1550.002** - Use Alternate Authentication Material: Pass the Hash
- **T1047** - Windows Management Instrumentation

### Collection (TA0009)
- **T1560** - Archive Collected Data
- **T1213** - Data from Information Repositories

### Exfiltration (TA0010)
- **T1041** - Exfiltration Over C2 Channel
- **T1048.003** - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

## NIST References

- **NIST SP 800-115** - Technical Guide to Information Security Testing and Assessment
- **NIST SP 800-53 Rev. 5** - Security and Privacy Controls (CA-8: Penetration Testing)
- **NIST SP 800-53A** - Assessing Security and Privacy Controls (CA-8 assessment procedures)
- **NIST CSF 2.0** - Identify, Protect, Detect, Respond, Recover functions

## Industry Frameworks

- **PTES** - Penetration Testing Execution Standard (Pre-engagement, Intelligence Gathering, Threat Modeling, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting)
- **OSSTMM** - Open Source Security Testing Methodology Manual v3
- **TIBER-EU** - European Central Bank Threat Intelligence-Based Ethical Red Teaming
- **CBEST** - Bank of England intelligence-led penetration testing framework
- **CREST** - Council of Registered Ethical Security Testers certification standards
- **STAR** - Simulated Targeted Attack and Response (Bank of Canada)

## Compliance Alignments

| Framework | Control | Description |
|---|---|---|
| PCI DSS 4.0 | 11.4 | External and internal penetration testing |
| SOC 2 | CC7.1 | Identification and management of vulnerabilities |
| ISO 27001 | A.18.2.3 | Technical compliance review |
| HIPAA | 164.308(a)(8) | Evaluation of security measures |
| FFIEC | IS.2.M.7 | Penetration testing program |
