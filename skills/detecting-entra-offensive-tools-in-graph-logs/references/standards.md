# Standards and Framework Mapping

## NIST CSF 2.0

| ID | Name | Rationale |
|----|------|-----------|
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events | Hunting the Graph activity tables continuously monitors directory API usage to find offensive-tool activity. |

## MITRE ATT&CK

| ID | Name | Rationale |
|----|------|-----------|
| T1078.004 | Valid Accounts: Cloud Accounts | Core technique: adversaries use valid cloud credentials/tokens to query the Graph APIs; these hunts detect that usage. |
| T1087.004 | Account Discovery: Cloud Account | The detected enumeration sweeps cloud accounts. |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Sweeps enumerate cloud groups and roles. |
| T1526 | Cloud Service Discovery | Broad directory enumeration is cloud service discovery. |

## Supporting References

- AADGraphActivityLogs (Microsoft Learn) — https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadgraphactivitylogs
- MicrosoftGraphActivityLogs overview — https://learn.microsoft.com/graph/microsoft-graph-activity-logs-overview
- Invictus-IR detection writeup — https://www.invictus-ir.com/news/the-missing-link-aadgraphactivitylogs-finally-arrives
- MITRE T1078.004 — https://attack.mitre.org/techniques/T1078/004/
