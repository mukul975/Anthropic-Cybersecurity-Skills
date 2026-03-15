# API Reference: Lateral Movement Detection

## Windows Event Log IDs

| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Successful logon (Logon_Type 3=network, 10=RDP) |
| 4625 | Security | Failed logon attempt |
| 4648 | Security | Explicit credential logon (runas) |
| 4672 | Security | Special privileges assigned (admin logon) |
| 4769 | Security | Kerberos TGS request (Pass-the-Ticket) |
| 5140 | Security | Network share access (C$, ADMIN$, IPC$) |
| 7045 | System | New service installed (PsExec) |

## Sysmon Event Codes

| Event Code | Description |
|------------|-------------|
| 1 | Process creation with command line |
| 3 | Network connection |
| 10 | Process access (LSASS credential dumping) |
| 17/18 | Named pipe created/connected (PsExec) |

## MITRE ATT&CK Techniques (TA0008)

| Technique | ID | Detection Signal |
|-----------|----|-----------------|
| Pass-the-Hash | T1550.002 | NTLM Type 3 logon to multiple hosts |
| PsExec | T1021.002 | PSEXESVC service creation + named pipe |
| WMI Execution | T1047 | WmiPrvSE spawning cmd/powershell |
| RDP | T1021.001 | Logon_Type 10 to multiple targets |
| SMB Admin Share | T1021.002 | EventCode 5140 on C$/ADMIN$ |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `csv` | stdlib | Parse exported Windows event logs |
| `json` | stdlib | Report output generation |
| `collections` | stdlib | Event aggregation and counting |

## References

- MITRE ATT&CK Lateral Movement: https://attack.mitre.org/tactics/TA0008/
- Splunk Security Essentials: https://splunkbase.splunk.com/app/3435
- Sigma rules (lateral movement): https://github.com/SigmaHQ/sigma
- Microsoft Defender for Identity: https://learn.microsoft.com/en-us/defender-for-identity/
