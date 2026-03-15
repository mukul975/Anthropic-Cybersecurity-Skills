# Standards and Framework References

## MITRE ATT&CK
| Technique ID | Name | Tactic |
|-------------|------|--------|
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1569.002 | System Services: Service Execution | Execution |

## CVE Details
- **CVE-2017-0143** through **CVE-2017-0148** - Multiple SMBv1 remote code execution vulnerabilities
- **MS17-010** - Microsoft Security Bulletin (March 14, 2017)
- **CVSS Score:** 9.3 (Critical)
- **Affected:** Windows XP through Windows Server 2016

## Affected Systems
| OS | Version | Vulnerable |
|----|---------|-----------|
| Windows XP | SP3 | Yes (no longer supported) |
| Windows 7 | SP1 | Yes (patched with KB4012212) |
| Windows Server 2008 | R2 SP1 | Yes (patched with KB4012212) |
| Windows Server 2012 | R2 | Yes (patched with KB4012213) |
| Windows 10 | 1607 and earlier | Yes (patched with KB4013198) |
| Windows Server 2016 | RTM | Yes (patched with KB4013429) |

## NIST NVD References
- CVE-2017-0144: Buffer overflow in SMBv1 server
- Allows remote attackers to execute arbitrary code via crafted packets

## Detection Signatures
- Snort SID 41978: SMB EternalBlue exploit attempt
- Suricata: ET EXPLOIT Possible MS17-010 SMB Request
