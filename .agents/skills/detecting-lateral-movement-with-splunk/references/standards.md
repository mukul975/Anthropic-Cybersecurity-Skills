# Standards and References - Lateral Movement Detection with Splunk

## MITRE ATT&CK Lateral Movement (TA0008)

| Technique | Name | Event Indicators |
|-----------|------|-----------------|
| T1021.001 | Remote Desktop Protocol | Logon Type 10, RDP certificate events |
| T1021.002 | SMB/Windows Admin Shares | Logon Type 3, ADMIN$/C$/IPC$ access |
| T1021.003 | Distributed COM | Logon Type 3, DCOM process creation |
| T1021.004 | SSH | OpenSSH authentication events |
| T1021.006 | Windows Remote Management | WinRM/WSMan logon events |
| T1047 | Windows Management Instrumentation | WMI remote process creation |
| T1569.002 | Service Execution | PsExec service install + Type 3 logon |
| T1570 | Lateral Tool Transfer | File copy over SMB/RDP |
| T1550.002 | Pass the Hash | Type 3 logon with NTLM authentication |
| T1550.003 | Pass the Ticket | Kerberos TGS without preceding TGT |

## Windows Logon Types Reference

| Type | Name | Description |
|------|------|-------------|
| 2 | Interactive | Local console logon |
| 3 | Network | SMB, mapped drives, WinRM |
| 4 | Batch | Scheduled task execution |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth |
| 9 | NewCredentials | RunAs /netonly |
| 10 | RemoteInteractive | RDP, Terminal Services |
| 11 | CachedInteractive | Cached domain logon |

## Key Windows Event IDs for Lateral Movement

| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Successful account logon |
| 4625 | Security | Failed account logon |
| 4648 | Security | Logon with explicit credentials |
| 4672 | Security | Special privileges assigned (admin logon) |
| 4768 | Security | Kerberos TGT requested |
| 4769 | Security | Kerberos TGS requested |
| 4776 | Security | NTLM credential validation |
| 5140 | Security | Network share accessed |
| 5145 | Security | Network share object access check |
| 7045 | System | New service installed |
| 1 | Sysmon | Process creation |
| 3 | Sysmon | Network connection |

## Splunk Data Model References

- `Authentication` data model for login events
- `Network_Traffic` data model for connection data
- `Endpoint.Processes` for process creation events
- `Change.Endpoint_Changes` for service installations

## Authentication Protocol Indicators

| Protocol | Lateral Movement | Event Indicators |
|----------|-----------------|-----------------|
| NTLM | Pass-the-Hash | Event 4776, NtLmSsp package |
| Kerberos | Pass-the-Ticket | Event 4768/4769, ticket anomalies |
| CredSSP | RDP | Event 4624 Type 10 |
| WSMan | WinRM | Event 4624 Type 3, WSMan source |
