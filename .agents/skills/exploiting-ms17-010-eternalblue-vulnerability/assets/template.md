# MS17-010 EternalBlue Assessment Template

## Summary
| Hosts Scanned | SMB Open | Vulnerable | Exploited |
|--------------|----------|-----------|-----------|
| | | | |

## Vulnerable Hosts
| IP | OS | Patch Level | Exploited | Impact |
|----|----|----|-----------|--------|
| | | Missing MS17-010 | Yes/No | SYSTEM access |

## Exploitation Evidence
- Target: [IP]
- Method: [Metasploit/Manual]
- Payload: [Meterpreter/Beacon]
- Access Level: SYSTEM
- Screenshot: [Reference]

## Recommendations
1. Apply MS17-010 patch immediately
2. Disable SMBv1 protocol
3. Block port 445 at perimeter
4. Segment legacy systems

## MITRE ATT&CK
- T1210 - Exploitation of Remote Services
