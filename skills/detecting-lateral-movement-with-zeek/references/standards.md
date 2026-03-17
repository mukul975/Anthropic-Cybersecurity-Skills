# Standards and References

## MITRE ATT&CK Mappings

### Tactic: Lateral Movement (TA0008)

Lateral Movement consists of techniques that adversaries use to enter and control remote
systems on a network. The adversary's primary goal is to move through the environment
to reach their ultimate target.

- **Reference**: https://attack.mitre.org/tactics/TA0008/

### Techniques Covered

| Technique ID | Name | Detection Method |
|---|---|---|
| T1021 | Remote Services | Monitor conn.log for internal connections on service ports (445, 3389, 135, 5985) |
| T1021.001 | Remote Desktop Protocol | Zeek rdp.log analysis — workstation-to-workstation RDP, multi-hop pivoting |
| T1021.002 | SMB/Windows Admin Shares | Zeek smb_mapping.log — access to C$, ADMIN$, IPC$ from non-admin hosts |
| T1570 | Lateral Tool Transfer | Zeek smb_files.log — executable files written to remote shares |
| T1550.002 | Pass the Hash | Zeek ntlm.log — NTLM auth bursts from single host, NTLM in Kerberos environments |
| T1003.006 | OS Credential Dumping: DCSync | Zeek dce_rpc.log — DRSGetNCChanges calls from non-DC sources |

### Related Techniques (Context)

| Technique ID | Name | Relevance |
|---|---|---|
| T1569.002 | System Services: Service Execution | PsExec creates a service via SVCCTL — detected in dce_rpc.log |
| T1076 | Remote Desktop Protocol (deprecated) | Merged into T1021.001 |
| T1077 | Windows Admin Shares (deprecated) | Merged into T1021.002 |
| T1097 | Pass the Ticket | Kerberos ticket anomalies in kerberos.log |

## Zeek Documentation

### Core References

- **Zeek Documentation**: https://docs.zeek.org/en/current/
- **Zeek Script Reference**: https://docs.zeek.org/en/current/script-reference/index.html
- **Zeek Log Files**: https://docs.zeek.org/en/current/log-files.html

### Protocol Analyzers

- **SMB Analyzer**: https://docs.zeek.org/en/current/scripts/base/protocols/smb/index.html
- **DCE-RPC Analyzer**: https://docs.zeek.org/en/current/scripts/base/protocols/dce-rpc/index.html
- **RDP Analyzer**: https://docs.zeek.org/en/current/scripts/base/protocols/rdp/index.html
- **Kerberos Analyzer**: https://docs.zeek.org/en/current/scripts/base/protocols/krb/index.html
- **NTLM Analyzer**: https://docs.zeek.org/en/current/scripts/base/protocols/ntlm/index.html

### Notice Framework

- **Notice Framework**: https://docs.zeek.org/en/current/frameworks/notice.html
- **Notice Types**: https://docs.zeek.org/en/current/scripts/base/frameworks/notice/main.zeek.html

## Additional Resources

- **SANS Zeek Cheat Sheet**: https://www.sans.org/posters/zeek-cheat-sheet/
- **Corelight Zeek Packages**: https://github.com/corelight
- **Zeek Package Manager**: https://packages.zeek.org/
- **MITRE ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/

## Key RPC Interfaces for Detection

| Interface UUID | Endpoint | Relevant Operations |
|---|---|---|
| `367abb81-9844-35f1-ad32-98f038001003` | svcctl | CreateServiceW (opnum 12), StartServiceW (opnum 19) |
| `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | drsuapi | DRSGetNCChanges (opnum 3), DRSBind (opnum 0) |
| `4b324fc8-1670-01d3-1278-5a47bf6ee188` | srvsvc | NetShareEnumAll (opnum 15) |

## Detection Quality Indicators

- **High Confidence**: DCSync from non-DC, PsExec service creation + admin share write
- **Medium Confidence**: Admin share access from non-admin host, workstation-to-workstation RDP
- **Low Confidence (needs context)**: NTLM authentication bursts, single admin share access
