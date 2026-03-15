# API Reference: Hunting for T1098 Account Manipulation

## Key Windows Security Event IDs

| Event ID | Description | T1098 Relevance |
|----------|-------------|-----------------|
| 4738 | User account changed | Account property modification |
| 4728 | Member added to global security group | Domain Admins, etc. |
| 4732 | Member added to local security group | Administrators, etc. |
| 4756 | Member added to universal security group | Enterprise Admins |
| 4729 | Member removed from global security group | Evidence cleanup |
| 4670 | Permissions on object changed | ACL manipulation |
| 5136 | Directory service object modified | SID History, SPNs |
| 4724 | Password reset attempted | Credential takeover |
| 4781 | Account name changed | Account rename evasion |

## Privileged Groups to Monitor

| Group | Risk | Impact |
|-------|------|--------|
| Domain Admins | Critical | Full domain control |
| Enterprise Admins | Critical | Forest-wide admin |
| Schema Admins | Critical | AD schema modification |
| Administrators | High | Local admin on DCs |
| Backup Operators | High | Read any file, backup SAM |
| DNS Admins | High | DLL injection on DCs |
| Account Operators | Medium | Create/modify accounts |

## Sensitive AD Attributes

| Attribute | Attack Technique |
|-----------|-----------------|
| SIDHistory | T1134.005 - SID History Injection |
| servicePrincipalName | T1558.003 - Kerberoasting setup |
| msDS-AllowedToDelegateTo | Constrained delegation abuse |
| msDS-AllowedToActOnBehalfOfOtherIdentity | RBCD attack |
| AdminCount | AdminSDHolder persistence |
| userAccountControl | Account flag manipulation |

## python-evtx Parsing

```python
import Evtx.Evtx as evtx

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml_str = record.xml()
        # Parse XML to extract EventID and Data fields
```

Install: `pip install python-evtx lxml`

## MITRE T1098 Sub-Techniques

| ID | Name | Key Indicator |
|----|------|---------------|
| T1098.001 | Additional Cloud Credentials | New keys/certs added |
| T1098.002 | Additional Email Delegate Access | Mailbox permission grants |
| T1098.003 | Additional Cloud Roles | Role assignment changes |
| T1098.004 | SSH Authorized Keys | authorized_keys modification |
| T1098.005 | Device Registration | Rogue device enrollment |

## References

- MITRE T1098: https://attack.mitre.org/techniques/T1098/
- CISA Eviction Guide: https://www.cisa.gov/eviction-strategies-tool/info-attack/T1098
- Windows Event Mapping: https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/
- python-evtx: https://github.com/williballenthin/python-evtx
