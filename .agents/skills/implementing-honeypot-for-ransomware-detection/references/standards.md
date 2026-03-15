# Standards & References - Honeypot for Ransomware Detection

## MITRE ATT&CK
- T1486: Data Encrypted for Impact (detection via canary file modification)
- T1021.002: SMB/Windows Admin Shares (detection via honeypot share access)
- T1083: File and Directory Discovery (detection via honeypot folder browsing)

## NIST SP 800-53 Rev 5
- SI-4: System Monitoring (honeypots as monitoring component)
- AU-6: Audit Record Review, Analysis, and Reporting (canary file audit logging)

## CIS Controls v8
- Control 13.1: Centralize security event alerting (integrate honeypot alerts into SIEM)
- Control 13.8: Deploy intrusion detection/prevention systems

## Tools Documentation
- Thinkst Canary: https://canary.tools/
- Canarytokens: https://canarytokens.org/
- OpenCanary: https://github.com/thinkst/opencanary
- FSRM: https://learn.microsoft.com/en-us/windows-server/storage/fsrm/fsrm-overview
- Elastic Ransomware Protection: https://www.elastic.co/security-labs/ransomware-in-the-honeypot-how-we-capture-keys
