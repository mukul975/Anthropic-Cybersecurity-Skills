# Standards and References - DCSync Domain Persistence

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|-------------|------|--------|
| T1003.006 | OS Credential Dumping: DCSync | Credential Access |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Credential Access |
| T1222.001 | File and Directory Permissions Modification | Defense Evasion |
| T1098 | Account Manipulation | Persistence |
| T1078.002 | Valid Accounts: Domain Accounts | Persistence |

## Key Research

- MITRE ATT&CK T1003.006: https://attack.mitre.org/techniques/T1003/006/
- Netwrix: DCSync Attack Using Mimikatz Detection
- JumpCloud: What Is DCSync? Critical AD Attack Explained
- The Hacker Recipes: DCSync technique documentation
- Atomic Red Team T1003.006 test procedures

## Threat Actor Usage

- APT28 (Fancy Bear) - DCSync for credential harvesting
- APT29 (Cozy Bear) - SolarWinds campaign used DCSync
- FIN6 - Financial cybercrime group
- Wizard Spider - Ryuk ransomware campaigns
