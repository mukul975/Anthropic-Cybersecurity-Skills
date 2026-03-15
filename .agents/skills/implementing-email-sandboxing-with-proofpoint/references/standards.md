# Standards & References: Email Sandboxing with Proofpoint

## MITRE ATT&CK Coverage
- **T1566.001**: Phishing: Spearphishing Attachment (primary detection)
- **T1566.002**: Phishing: Spearphishing Link (URL Defense)
- **T1204.001/002**: User Execution: Malicious Link/File
- **T1059**: Command and Scripting Interpreter (macro detection)
- **T1027**: Obfuscated Files or Information

## NIST Guidelines
- **NIST SP 800-177**: Trustworthy Email - attachment security
- **NIST SP 800-83 Rev.1**: Guide to Malware Incident Prevention
- **NIST SP 800-53**: SI-3 Malicious Code Protection, SI-8 Spam Protection

## Proofpoint TAP API Endpoints
| Endpoint | Description |
|---|---|
| `/v2/siem/all` | All threat events for SIEM |
| `/v2/siem/messages/blocked` | Blocked message events |
| `/v2/siem/messages/delivered` | Delivered message events with threats |
| `/v2/siem/clicks/blocked` | Blocked URL click events |
| `/v2/siem/clicks/permitted` | Permitted URL click events |
| `/v2/people/vap` | Very Attacked People list |
| `/v2/campaign/{id}` | Campaign details |

## Sandbox File Types
| Category | Extensions | Action |
|---|---|---|
| Executables | .exe, .dll, .scr, .com | Detonate + Block |
| Office docs | .doc(x/m), .xls(x/m), .ppt(x/m) | Detonate |
| PDF | .pdf | Detonate |
| Archives | .zip, .rar, .7z, .tar.gz | Extract + Detonate |
| Scripts | .js, .vbs, .ps1, .bat, .cmd | Block |
| Disk images | .iso, .img, .vhd | Detonate |
