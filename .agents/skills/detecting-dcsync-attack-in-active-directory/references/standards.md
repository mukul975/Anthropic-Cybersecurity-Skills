# Standards and References - DCSync Attack Detection

## MITRE ATT&CK Credential Access (TA0006)

| Technique | Name | Relevance |
|-----------|------|-----------|
| T1003.006 | OS Credential Dumping: DCSync | Primary technique |
| T1003.001 | LSASS Memory | Often combined with DCSync for complete credential theft |
| T1003.003 | NTDS | Alternative to DCSync using ntdsutil or volume shadow copy |
| T1078.002 | Valid Accounts: Domain Accounts | Using dumped credentials |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Primary goal of KRBTGT hash extraction |
| T1222.001 | File and Directory Permissions Modification | Granting replication rights |

## Critical Replication GUIDs

| GUID | Permission Name | Risk |
|------|----------------|------|
| 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 | DS-Replication-Get-Changes | Required for DCSync |
| 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 | DS-Replication-Get-Changes-All | Includes confidential attributes (passwords) |
| 89e95b76-444d-4c62-991a-0facbeda640c | DS-Replication-Get-Changes-In-Filtered-Set | Partial replication rights |

## Windows Event IDs for DCSync Detection

| Event ID | Source | Description |
|----------|--------|-------------|
| 4662 | Security | Directory Service Object Access (primary detection) |
| 4624 | Security | Successful logon (correlate source of replication) |
| 4672 | Security | Special privileges assigned (admin logon) |
| 4738 | Security | User account changed (permission grants) |
| 5136 | Security | Directory Service Object modified (ACL changes) |

## Known Threat Actors Using DCSync

| Actor | Context |
|-------|---------|
| APT29 (Cozy Bear) | Used DCSync in SolarWinds campaign |
| FIN6 | DCSync for credential harvesting in retail/hospitality |
| Wizard Spider | TrickBot/Conti ransomware using DCSync pre-encryption |
| APT28 (Fancy Bear) | DCSync in government network intrusions |
| LAPSUS$ | DCSync after AD compromise for data theft |

## Legitimate Replication Sources

| Source | Reason | How to Distinguish |
|--------|--------|--------------------|
| Domain Controllers | Normal AD replication | Computer account ends with $ |
| Azure AD Connect | Hybrid identity sync | MSOL_ service account |
| Backup Software | AD backup operations | Documented service accounts |
| Migration Tools | Cross-forest migrations | Temporary, documented operations |
