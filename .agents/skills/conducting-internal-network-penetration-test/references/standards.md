# Standards — Internal Network Penetration Testing

## Frameworks
- PTES: http://www.pentest-standard.org/
- OSSTMM v3: https://www.isecom.org/OSSTMM.3.pdf
- NIST SP 800-115: https://csrc.nist.gov/publications/detail/sp/800-115/final
- MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/

## Key MITRE ATT&CK Techniques for Internal Testing

| Tactic | Technique | ID |
|--------|-----------|----|
| Discovery | Network Service Discovery | T1046 |
| Credential Access | LLMNR/NBT-NS Poisoning | T1557.001 |
| Credential Access | Kerberoasting | T1558.003 |
| Credential Access | OS Credential Dumping | T1003 |
| Lateral Movement | Remote Services: SMB | T1021.002 |
| Lateral Movement | Pass the Hash | T1550.002 |
| Privilege Escalation | Domain Policy Modification | T1484 |
| Collection | Data from Network Shared Drive | T1039 |

## Compliance Requirements

| Standard | Internal Pentest Requirement |
|----------|----------------------------|
| PCI DSS v4.0 | Req 11.4.2 — Internal penetration testing annually |
| ISO 27001 | A.18.2.3 — Technical compliance review |
| SOC 2 | CC7.1 — Detection and monitoring |
| NIST CSF | PR.IP-12, DE.CM |
